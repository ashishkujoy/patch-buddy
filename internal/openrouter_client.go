package internal

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	openrouter "github.com/OpenRouterTeam/go-sdk"
	"github.com/OpenRouterTeam/go-sdk/models/components"
	"github.com/OpenRouterTeam/go-sdk/models/operations"
)

// defaultOpenRouterModel is used when PATCHBOT_MODEL is unset. OpenRouter's
// model catalog is versioned independently of this SDK - confirm the slug
// still exists (openrouter.ai/models or Models.List()) before relying on it.
const defaultOpenRouterModel = "anthropic/claude-opus-5"

const proposePatchToolName = "propose_patch"

// chatSender is the one OpenRouter SDK method openRouterClient calls,
// isolated so propose()'s request-building and response-parsing can be unit
// tested without a real OpenRouter API call. *openrouter.Chat satisfies it.
type chatSender interface {
	Send(
		ctx context.Context,
		chatRequest components.ChatRequest,
		xOpenRouterMetadata *components.MetadataLevel,
		opts ...operations.Option,
	) (*operations.SendChatCompletionRequestResponse, error)
}

// openRouterClient is the modelClient implementation backed by OpenRouter.
type openRouterClient struct {
	chat  chatSender
	model string
}

// NewOpenRouterFixer builds a BreakingChangeFixer backed by OpenRouter, or
// returns nil if OPENROUTER_API_KEY isn't set - callers pass a nil
// BreakingChangeFixer to UpdateDependencies to skip the AI fix loop
// entirely, which is the right default when no key is configured.
func NewOpenRouterFixer() BreakingChangeFixer {
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" {
		return nil
	}
	model := os.Getenv("PATCHBOT_MODEL")
	if model == "" {
		model = defaultOpenRouterModel
	}
	sdk := openrouter.New(openrouter.WithSecurity(apiKey))
	return &openRouterFixer{client: &openRouterClient{chat: sdk.Chat, model: model}}
}

type openRouterFixer struct {
	client modelClient
}

func (f *openRouterFixer) Fix(ctx context.Context, workdir string, dependency *UpgradableFinding, buildStderr string) *FixAttempt {
	return attemptBreakingChangeFix(ctx, f.client, workdir, dependency, buildStderr)
}

func (c *openRouterClient) propose(ctx context.Context, req fixRequest) ([]patch, error) {
	chatRequest := components.ChatRequest{
		Model: new(c.model),
		Messages: []components.ChatMessages{
			components.CreateChatMessagesSystem(components.ChatSystemMessage{
				Role: components.ChatSystemMessageRoleSystem,
				Content: components.CreateChatSystemMessageContentStr(
					"You are helping fix a Go build broken by a dependency upgrade. " +
						"You will be given the compiler error, the source of every file it " +
						"references, and Go documentation for the old and new API. Call " +
						proposePatchToolName + " one or more times with an exact search/replace " +
						"patch for each fix needed. The search text must match the file " +
						"content exactly, including whitespace, and must appear exactly once.",
				),
			}),
			components.CreateChatMessagesUser(components.ChatUserMessage{
				Role:    components.ChatUserMessageRoleUser,
				Content: components.CreateChatUserMessageContentStr(renderFixPrompt(req)),
			}),
		},
		Tools:      []components.ChatFunctionTool{proposePatchTool()},
		ToolChoice: proposePatchToolChoice(),
	}

	res, err := c.chat.Send(ctx, chatRequest, nil)
	if err != nil {
		return nil, err
	}
	if res.ChatResult == nil {
		return nil, fmt.Errorf("openrouter: expected a non-streaming chat result")
	}
	if len(res.ChatResult.Choices) == 0 {
		return nil, fmt.Errorf("openrouter: response had no choices")
	}

	toolCalls := res.ChatResult.Choices[0].Message.ToolCalls
	patches := make([]patch, 0, len(toolCalls))
	for _, call := range toolCalls {
		if call.Function.Name != proposePatchToolName {
			continue
		}
		p, err := parsePatchArguments(call.Function.Arguments)
		if err != nil {
			return nil, err
		}
		patches = append(patches, p)
	}
	return patches, nil
}

func proposePatchTool() components.ChatFunctionTool {
	return components.CreateChatFunctionToolChatFunctionToolFunction(components.ChatFunctionToolFunction{
		Type: components.ChatFunctionToolTypeFunction,
		Function: components.ChatFunctionToolFunctionFunction{
			Name: proposePatchToolName,
			Description: new(
				"Propose an exact search/replace patch to one file to fix the build error.",
			),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"file_path": map[string]any{
						"type":        "string",
						"description": "Path to the file to patch, relative to the repository root.",
					},
					"search": map[string]any{
						"type": "string",
						"description": "The exact existing source text to replace, including enough " +
							"surrounding context to match exactly once in the file.",
					},
					"replace": map[string]any{
						"type":        "string",
						"description": "The replacement source text.",
					},
				},
				"required": []string{"file_path", "search", "replace"},
			},
		},
	})
}

func proposePatchToolChoice() *components.ChatToolChoice {
	choice := components.CreateChatToolChoiceChatNamedToolChoice(components.ChatNamedToolChoice{
		Type:     components.ChatNamedToolChoiceTypeFunction,
		Function: components.ChatNamedToolChoiceFunction{Name: proposePatchToolName},
	})
	return &choice
}

// renderFixPrompt lays out everything §6 of
// patchbot-breaking-upgrade-context.md wants as seed context: the compiler
// error, the referenced source, the old/new API docs, the OSV summary, and
// what earlier iterations already tried.
func renderFixPrompt(req fixRequest) string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "## Dependency change\n%s -> %s\n\n", req.OldModule, req.NewModule)
	if req.OSVSummary != "" {
		_, _ = fmt.Fprintf(&b, "## Why this upgrade happened\n%s\n\n", req.OSVSummary)
	}

	_, _ = fmt.Fprintf(&b, "## Compiler error\n```\n%s\n```\n\n", req.BuildStderr)

	if len(req.Files) > 0 {
		b.WriteString("## Affected files\n")
		for _, path := range sortedKeys(req.Files) {
			_, _ = fmt.Fprintf(&b, "### %s\n```go\n%s\n```\n\n", path, req.Files[path])
		}
	}

	if req.OldModuleDoc != "" {
		_, _ = fmt.Fprintf(&b, "## `go doc %s`\n```\n%s\n```\n\n", req.OldModule, req.OldModuleDoc)
	}
	if req.NewModuleDoc != "" {
		_, _ = fmt.Fprintf(&b, "## `go doc %s`\n```\n%s\n```\n\n", req.NewModule, req.NewModuleDoc)
	}

	if len(req.PriorAttempts) > 0 {
		b.WriteString("## Prior attempts (did not fix the build)\n")
		for i, attempt := range req.PriorAttempts {
			_, _ = fmt.Fprintf(&b, "### Attempt %d\n", i+1)
			for _, p := range attempt.Patches {
				_, _ = fmt.Fprintf(&b, "Patched %s:\n- search: %q\n- replace: %q\n", p.FilePath, p.Search, p.Replace)
			}
			_, _ = fmt.Fprintf(&b, "Resulting build error:\n```\n%s\n```\n\n", attempt.BuildStderr)
		}
	}

	return b.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

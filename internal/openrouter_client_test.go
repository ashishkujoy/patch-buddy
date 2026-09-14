package internal

import (
	"context"
	"errors"
	"testing"

	"github.com/OpenRouterTeam/go-sdk/models/components"
	"github.com/OpenRouterTeam/go-sdk/models/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeChatSender fakes the one OpenRouter SDK call openRouterClient makes,
// so propose()'s request-building and response-parsing can be tested
// without a real API call.
type fakeChatSender struct {
	response *operations.SendChatCompletionRequestResponse
	err      error
	lastReq  components.ChatRequest
}

func (f *fakeChatSender) Send(
	_ context.Context,
	chatRequest components.ChatRequest,
	_ *components.MetadataLevel,
	_ ...operations.Option,
) (*operations.SendChatCompletionRequestResponse, error) {
	f.lastReq = chatRequest
	return f.response, f.err
}

func chatResultWithToolCalls(calls ...components.ChatToolCall) *operations.SendChatCompletionRequestResponse {
	result := components.ChatResult{
		Choices: []components.ChatChoice{
			{Message: components.ChatAssistantMessage{ToolCalls: calls}},
		},
	}
	return &operations.SendChatCompletionRequestResponse{
		ChatResult: &result,
		Type:       operations.SendChatCompletionRequestResponseTypeChatResult,
	}
}

func toolCall(name, arguments string) components.ChatToolCall {
	return components.ChatToolCall{
		ID:       "call_1",
		Type:     components.ChatToolCallTypeFunction,
		Function: components.ChatToolCallFunction{Name: name, Arguments: arguments},
	}
}

func Test_OpenRouterClient_Propose_ParsesProposedPatch(t *testing.T) {
	sender := &fakeChatSender{
		response: chatResultWithToolCalls(
			toolCall(proposePatchToolName, `{"file_path":"a.go","search":"old","replace":"new"}`),
		),
	}
	client := &openRouterClient{chat: sender, model: "anthropic/claude-opus-5"}

	patches, err := client.propose(context.Background(), fixRequest{OldModule: "old/mod", NewModule: "new/mod"})
	require.NoError(t, err)
	require.Len(t, patches, 1)
	assert.Equal(t, patch{FilePath: "a.go", Search: "old", Replace: "new"}, patches[0])

	assert.Equal(t, "anthropic/claude-opus-5", *sender.lastReq.Model)
	require.Len(t, sender.lastReq.Tools, 1)
	require.NotNil(t, sender.lastReq.ToolChoice)
}

func Test_OpenRouterClient_Propose_HandlesMultipleToolCallsAndIgnoresOthers(t *testing.T) {
	sender := &fakeChatSender{
		response: chatResultWithToolCalls(
			toolCall(proposePatchToolName, `{"file_path":"a.go","search":"a","replace":"b"}`),
			toolCall("some_other_tool", `{}`),
			toolCall(proposePatchToolName, `{"file_path":"b.go","search":"c","replace":"d"}`),
		),
	}
	client := &openRouterClient{chat: sender, model: "m"}

	patches, err := client.propose(context.Background(), fixRequest{})
	require.NoError(t, err)
	require.Len(t, patches, 2)
	assert.Equal(t, "a.go", patches[0].FilePath)
	assert.Equal(t, "b.go", patches[1].FilePath)
}

func Test_OpenRouterClient_Propose_NoToolCalls_ReturnsEmptyPatches(t *testing.T) {
	sender := &fakeChatSender{response: chatResultWithToolCalls()}
	client := &openRouterClient{chat: sender, model: "m"}

	patches, err := client.propose(context.Background(), fixRequest{})
	require.NoError(t, err)
	assert.Empty(t, patches)
}

func Test_OpenRouterClient_Propose_MalformedArguments_ReturnsError(t *testing.T) {
	sender := &fakeChatSender{
		response: chatResultWithToolCalls(toolCall(proposePatchToolName, `not json`)),
	}
	client := &openRouterClient{chat: sender, model: "m"}

	_, err := client.propose(context.Background(), fixRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse propose_patch arguments")
}

func Test_OpenRouterClient_Propose_SendError_Propagates(t *testing.T) {
	sender := &fakeChatSender{err: errors.New("network down")}
	client := &openRouterClient{chat: sender, model: "m"}

	_, err := client.propose(context.Background(), fixRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network down")
}

func Test_OpenRouterClient_Propose_NilChatResult_ReturnsError(t *testing.T) {
	sender := &fakeChatSender{response: &operations.SendChatCompletionRequestResponse{}}
	client := &openRouterClient{chat: sender, model: "m"}

	_, err := client.propose(context.Background(), fixRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected a non-streaming chat result")
}

func Test_OpenRouterClient_Propose_NoChoices_ReturnsError(t *testing.T) {
	sender := &fakeChatSender{response: &operations.SendChatCompletionRequestResponse{
		ChatResult: &components.ChatResult{},
	}}
	client := &openRouterClient{chat: sender, model: "m"}

	_, err := client.propose(context.Background(), fixRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no choices")
}

func Test_NewOpenRouterFixer_ReturnsNilWithoutAPIKey(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")
	assert.Nil(t, NewOpenRouterFixer())
}

func Test_NewOpenRouterFixer_ReturnsFixerWithAPIKey(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "test-key")
	assert.NotNil(t, NewOpenRouterFixer())
}

func Test_RenderFixPrompt_IncludesAllProvidedContext(t *testing.T) {
	req := fixRequest{
		OSVSummary:   "auth bypass",
		OldModule:    "old/mod",
		NewModule:    "new/mod",
		OldModuleDoc: "old doc",
		NewModuleDoc: "new doc",
		BuildStderr:  "compile error",
		Files:        map[string]string{"a.go": "package a"},
		PriorAttempts: []attemptRecord{
			{Patches: []patch{{FilePath: "a.go", Search: "x", Replace: "y"}}, BuildStderr: "still broken"},
		},
	}

	prompt := renderFixPrompt(req)
	assert.Contains(t, prompt, "old/mod -> new/mod")
	assert.Contains(t, prompt, "auth bypass")
	assert.Contains(t, prompt, "compile error")
	assert.Contains(t, prompt, "a.go")
	assert.Contains(t, prompt, "package a")
	assert.Contains(t, prompt, "old doc")
	assert.Contains(t, prompt, "new doc")
	assert.Contains(t, prompt, "Prior attempts")
	assert.Contains(t, prompt, "still broken")
}

func Test_RenderFixPrompt_OmitsEmptySections(t *testing.T) {
	prompt := renderFixPrompt(fixRequest{OldModule: "old", NewModule: "new", BuildStderr: "err"})
	assert.NotContains(t, prompt, "Why this upgrade happened")
	assert.NotContains(t, prompt, "Affected files")
	assert.NotContains(t, prompt, "go doc")
	assert.NotContains(t, prompt, "Prior attempts")
}

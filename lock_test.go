package main

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// mockDynamoClient implements dynamoLockClient using an in-memory map.
type mockDynamoClient struct {
	mu     sync.Mutex
	items  map[string]struct{}
	putErr error // if non-nil, PutItem returns this (non-conditional) error
}

func newMockDynamo() *mockDynamoClient {
	return &mockDynamoClient{items: make(map[string]struct{})}
}

func (m *mockDynamoClient) PutItem(_ context.Context, params *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := params.Item[lockPKAttr].(*dynamodbtypes.AttributeValueMemberS).Value
	if _, exists := m.items[key]; exists {
		return nil, &dynamodbtypes.ConditionalCheckFailedException{}
	}
	m.items[key] = struct{}{}
	return &dynamodb.PutItemOutput{}, nil
}

func (m *mockDynamoClient) DeleteItem(_ context.Context, params *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := params.Key[lockPKAttr].(*dynamodbtypes.AttributeValueMemberS).Value
	delete(m.items, key)
	return &dynamodb.DeleteItemOutput{}, nil
}

func TestAcquireLock_Success(t *testing.T) {
	mock := newMockDynamo()
	if err := acquireLock(context.Background(), mock, "test-table", "repo:tag"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, ok := mock.items["repo:tag"]; !ok {
		t.Error("lock item not present in DynamoDB after acquire")
	}
}

func TestAcquireLock_Timeout(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = struct{}{} // pre-lock so acquire always fails
	ctx, cancel := context.WithTimeout(context.Background(), 2*lockRetryDelay)
	defer cancel()
	if err := acquireLock(ctx, mock, "test-table", "repo:tag"); err == nil {
		t.Fatal("expected error when lock cannot be acquired, got nil")
	}
}

func TestAcquireLock_NonConditionalError(t *testing.T) {
	mock := newMockDynamo()
	mock.putErr = fmt.Errorf("network failure")
	if err := acquireLock(context.Background(), mock, "test-table", "repo:tag"); err == nil {
		t.Fatal("expected error on non-conditional PutItem failure, got nil")
	}
}

func TestReleaseLock(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = struct{}{}
	releaseLock(context.Background(), mock, "test-table", "repo:tag")
	if _, ok := mock.items["repo:tag"]; ok {
		t.Error("lock item still present after release")
	}
}

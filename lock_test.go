package main

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// mockDynamoClient implements dynamoLockClient using an in-memory map.
type mockDynamoClient struct {
	mu          sync.Mutex
	items       map[string]int64 // pk -> TTL unix timestamp
	putErr      error            // if non-nil, PutItem returns this (non-conditional) error
	deleteErrN  int              // fail DeleteItem this many times before succeeding
	deleteCalls int
}

func newMockDynamo() *mockDynamoClient {
	return &mockDynamoClient{items: make(map[string]int64)}
}

func (m *mockDynamoClient) PutItem(_ context.Context, params *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := params.Item[lockPKAttr].(*dynamodbtypes.AttributeValueMemberS).Value
	if existingTTL, exists := m.items[key]; exists {
		// Evaluate condition: attribute_not_exists(pk) OR ttl < :now
		// Key exists, so check if the stored TTL is expired relative to :now.
		nowAttr, hasNow := params.ExpressionAttributeValues[":now"]
		if !hasNow {
			return nil, &dynamodbtypes.ConditionalCheckFailedException{}
		}
		nowVal, _ := strconv.ParseInt(nowAttr.(*dynamodbtypes.AttributeValueMemberN).Value, 10, 64)
		if existingTTL >= nowVal {
			return nil, &dynamodbtypes.ConditionalCheckFailedException{}
		}
		// TTL is expired — allow overwrite.
	}
	ttlVal, _ := strconv.ParseInt(params.Item[lockTTLAttr].(*dynamodbtypes.AttributeValueMemberN).Value, 10, 64)
	m.items[key] = ttlVal
	return &dynamodb.PutItemOutput{}, nil
}

func (m *mockDynamoClient) DeleteItem(_ context.Context, params *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteCalls <= m.deleteErrN {
		return nil, fmt.Errorf("transient delete error")
	}
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
	mock.items["repo:tag"] = math.MaxInt64 // pre-lock that never expires
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

// TestAcquireLock_ExpiredTTL verifies that a lock whose TTL has passed but whose
// item has not yet been physically removed by DynamoDB can still be acquired.
func TestAcquireLock_ExpiredTTL(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = time.Now().Add(-time.Minute).Unix() // expired TTL
	if err := acquireLock(context.Background(), mock, "test-table", "repo:tag"); err != nil {
		t.Fatalf("expected lock acquisition to succeed over expired item, got %v", err)
	}
	if _, ok := mock.items["repo:tag"]; !ok {
		t.Error("lock item not present after acquiring over expired TTL")
	}
}

func TestReleaseLock(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = math.MaxInt64
	releaseLock(context.Background(), mock, "test-table", "repo:tag")
	if _, ok := mock.items["repo:tag"]; ok {
		t.Error("lock item still present after release")
	}
}

// TestReleaseLock_Retries verifies that releaseLock retries on transient errors
// and eventually deletes the item.
func TestReleaseLock_Retries(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = math.MaxInt64
	mock.deleteErrN = releaseMaxRetries - 1 // fail all but the last attempt
	releaseLock(context.Background(), mock, "test-table", "repo:tag")
	if _, ok := mock.items["repo:tag"]; ok {
		t.Error("lock item still present after release with retries")
	}
	if mock.deleteCalls != releaseMaxRetries {
		t.Errorf("expected %d DeleteItem calls, got %d", releaseMaxRetries, mock.deleteCalls)
	}
}

// TestReleaseLock_AllRetriesExhausted verifies that releaseLock does not panic
// or return an error when all retry attempts fail (TTL is the safety net).
func TestReleaseLock_AllRetriesExhausted(t *testing.T) {
	mock := newMockDynamo()
	mock.items["repo:tag"] = math.MaxInt64
	mock.deleteErrN = releaseMaxRetries // fail every attempt
	releaseLock(context.Background(), mock, "test-table", "repo:tag")
	if _, ok := mock.items["repo:tag"]; !ok {
		t.Error("lock item should still be present when all release attempts fail")
	}
	if mock.deleteCalls != releaseMaxRetries {
		t.Errorf("expected %d DeleteItem calls, got %d", releaseMaxRetries, mock.deleteCalls)
	}
}

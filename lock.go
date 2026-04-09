package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	lockPKAttr        = "pk"
	lockTTLAttr       = "ttl"
	lockTTL           = 60 * time.Second
	lockRetryDelay    = 1 * time.Second
	lockTimeout       = 30 * time.Second
	releaseMaxRetries = 3
	releaseRetryDelay = 500 * time.Millisecond
)

const lockConditionExpr = "attribute_not_exists(" + lockPKAttr + ") OR " + lockTTLAttr + " < :now"

// dynamoLockClient is the subset of dynamodb.Client used for locking.
type dynamoLockClient interface {
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// acquireLock attempts to create a lock item in DynamoDB using a conditional
// write. It retries until the context is cancelled or lockTimeout elapses.
func acquireLock(ctx context.Context, client dynamoLockClient, tableName string, key string) error {
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	for {
		now := strconv.FormatInt(time.Now().Unix(), 10)
		ttl := strconv.FormatInt(time.Now().Add(lockTTL).Unix(), 10)
		_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: aws.String(tableName),
			Item: map[string]dynamodbtypes.AttributeValue{
				lockPKAttr:  &dynamodbtypes.AttributeValueMemberS{Value: key},
				lockTTLAttr: &dynamodbtypes.AttributeValueMemberN{Value: ttl},
			},
			ConditionExpression: aws.String(lockConditionExpr),
			ExpressionAttributeValues: map[string]dynamodbtypes.AttributeValue{
				":now": &dynamodbtypes.AttributeValueMemberN{Value: now},
			},
		})
		if err == nil {
			// lock acquired
			return nil
		}
		var condErr *dynamodbtypes.ConditionalCheckFailedException
		if !errors.As(err, &condErr) {
			return fmt.Errorf("acquiring lock %q: %w", key, err)
		} else {
			slog.Debug("lock already exists, retrying...", "key", key, "retryDelay", lockRetryDelay, "error", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out acquiring lock %q: %w", key, ctx.Err())
		case <-time.After(lockRetryDelay):
		}
	}
}

// releaseLock deletes the lock item from DynamoDB. It retries up to
// releaseMaxRetries times. Errors are logged but not returned — the TTL will
// expire the lock automatically if all attempts fail.
func releaseLock(ctx context.Context, client dynamoLockClient, tableName, key string) {
	// Use a detached context so a cancelled parent doesn't prevent the release.
	releaseCtx := context.WithoutCancel(ctx)
	input := &dynamodb.DeleteItemInput{
		TableName: aws.String(tableName),
		Key: map[string]dynamodbtypes.AttributeValue{
			lockPKAttr: &dynamodbtypes.AttributeValueMemberS{Value: key},
		},
	}
	for attempt := range releaseMaxRetries {
		_, err := client.DeleteItem(releaseCtx, input)
		if err == nil {
			return
		}
		slog.WarnContext(ctx, "failed to release lock", "key", key, "attempt", attempt+1, "error", err)
		if attempt < releaseMaxRetries-1 {
			time.Sleep(releaseRetryDelay)
		}
	}
}

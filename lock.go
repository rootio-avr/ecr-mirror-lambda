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
	lockPKAttr     = "pk"
	lockTTLAttr    = "ttl"
	lockTTL        = 60 * time.Second
	lockRetryDelay = 1 * time.Second
	lockTimeout    = 30 * time.Second
)

const lockConditionExpr = "attribute_not_exists(" + lockPKAttr + ")"

// dynamoLockClient is the subset of dynamodb.Client used for locking.
type dynamoLockClient interface {
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// acquireLock attempts to create a lock item in DynamoDB using a conditional
// write. It retries until the context is cancelled or lockTimeout elapses.
func acquireLock(ctx context.Context, client dynamoLockClient, tableName, key string) error {
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	for {
		ttl := strconv.FormatInt(time.Now().Add(lockTTL).Unix(), 10)
		_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: aws.String(tableName),
			Item: map[string]dynamodbtypes.AttributeValue{
				lockPKAttr:  &dynamodbtypes.AttributeValueMemberS{Value: key},
				lockTTLAttr: &dynamodbtypes.AttributeValueMemberN{Value: ttl},
			},
			ConditionExpression: aws.String(lockConditionExpr),
		})
		if err == nil {
			return nil
		}
		var condErr *dynamodbtypes.ConditionalCheckFailedException
		if !errors.As(err, &condErr) {
			return fmt.Errorf("acquiring lock %q: %w", key, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out acquiring lock %q: %w", key, ctx.Err())
		case <-time.After(lockRetryDelay):
		}
	}
}

// releaseLock deletes the lock item from DynamoDB. Errors are logged but not
// returned — the TTL will expire the lock automatically if this fails.
func releaseLock(ctx context.Context, client dynamoLockClient, tableName, key string) {
	if _, err := client.DeleteItem(context.WithoutCancel(ctx), &dynamodb.DeleteItemInput{
		TableName: aws.String(tableName),
		Key: map[string]dynamodbtypes.AttributeValue{
			lockPKAttr: &dynamodbtypes.AttributeValueMemberS{Value: key},
		},
	}); err != nil {
		slog.WarnContext(ctx, "failed to release lock", "key", key, "error", err)
	}
}

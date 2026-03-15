# ecr-mirror-lambda

Automatically mirror [Root](https://root.io) remediated container images into your Amazon ECR — no polling, no manual steps.

When Root patches a vulnerability and pushes a new image tag, this Lambda receives a webhook, verifies its authenticity, and copies the image straight into your ECR. Deploy it once with Terraform and forget about it.

## How It Works

```
┌──────────┐    webhook     ┌──────────────────┐   crane.Copy   ┌──────────┐
│  Root.io  │ ────────────→ │  AWS Lambda       │ ─────────────→ │ Your ECR │
│ (cr.root) │  CloudEvents  │  (verify + copy)  │   IAM auth     │          │
└──────────┘               └──────────────────┘               └──────────┘
```

1. Root finishes remediating an image and sends a signed [CloudEvents](https://cloudevents.io/) webhook
2. The Lambda verifies the [Standard Webhooks](https://www.standardwebhooks.com/) HMAC-SHA256 signature
3. If valid, it copies the image from `cr.root.io` to your ECR using [crane](https://github.com/google/go-containerregistry)

No long-lived credentials — the Lambda uses its IAM role for ECR and reads secrets from AWS Secrets Manager.

## Prerequisites

You'll need:

- **AWS CLI** — configured with an active profile ([install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html))
- **Terraform** >= 1.5 ([install guide](https://developer.hashicorp.com/terraform/install))
- **Docker** ([install guide](https://docs.docker.com/get-docker/))
- **A Root account** with an API key

## Getting Started

The whole setup takes about 5 minutes.

### Step 1: Clone this repo

```sh
git clone https://github.com/root-io/ecr-mirror-lambda.git
cd ecr-mirror-lambda
```

### Step 2: Build and push the Lambda image

Replace `<ACCOUNT_ID>` and `<REGION>` with your values:

```sh
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1

# Log in to ECR
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Create a repo for the Lambda image (one-time)
aws ecr create-repository --repository-name root-ecr-mirror-lambda --region $AWS_REGION

# Build and push
docker build --platform linux/amd64 \
  -t $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/root-ecr-mirror-lambda:latest .
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/root-ecr-mirror-lambda:latest
```

### Step 3: Configure and deploy

```sh
cd terraform/
cp terraform.tfvars.example terraform.tfvars
```

Open `terraform.tfvars` and fill in your values:

```hcl
aws_region       = "us-east-1"
dst_repo         = "root-mirror"
lambda_image_uri = "123456789012.dkr.ecr.us-east-1.amazonaws.com/root-ecr-mirror-lambda:latest"

# You'll get these from Root (see Step 4)
webhook_signing_secret = ""
root_api_key           = "root_..."
```

Then deploy:

```sh
terraform init
terraform apply
```

When it finishes, you'll see two outputs:

```
webhook_url       = "https://xxxxx.lambda-url.us-east-1.on.aws/"
ecr_repository_url = "123456789012.dkr.ecr.us-east-1.amazonaws.com/root-mirror"
```

### Step 4: Register the webhook in Root

Copy the `webhook_url` from the Terraform output and create a webhook subscription:

```sh
curl -X POST https://api.root.io/v3/settings/webhooks \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://xxxxx.lambda-url.us-east-1.on.aws/",
    "description": "Mirror to ECR",
    "event_types": ["io.root.cr.image.created.v1"]
  }'
```

The response includes a `secret` field — copy it, paste it into `terraform.tfvars` as `webhook_signing_secret`, and run `terraform apply` once more.

That's it. Every new Root remediated image will now automatically appear in your ECR.

## Verifying It Works

**Watch the logs:**

```sh
aws logs tail /aws/lambda/root-ecr-mirror --follow
```

On a successful mirror, you'll see:

```
INFO received event  webhook_id=whmsg_... event_id=evt_... type=io.root.cr.image.created.v1 image_repo=library/nginx image_tag=1.25.4-amd64-root
INFO copying image   webhook_id=whmsg_... src=cr.root.io/library/nginx:1.25.4-amd64-root dst=123456789012.dkr.ecr.us-east-1.amazonaws.com/root-mirror/library/nginx:1.25.4-amd64-root
INFO image copied successfully  webhook_id=whmsg_...
```

**Check ECR:**

```sh
aws ecr list-images --repository-name root-mirror/library/nginx --region us-east-1
```

## Teardown

To remove everything:

```sh
cd terraform/
terraform destroy
```

This cleanly deletes the Lambda, IAM role, secrets, ECR repository, CloudWatch log group, and Function URL.

## Configuration

### Terraform Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `aws_region` | No | `us-east-1` | AWS region to deploy into |
| `dst_repo` | No | `root-mirror` | Base ECR repository name. Images appear as `<dst_repo>/<image_name>:<tag>` |
| `lambda_image_uri` | **Yes** | — | ECR URI of the built Lambda container image |
| `root_registry_host` | No | `cr.root.io` | Root registry hostname |
| `webhook_signing_secret` | **Yes** | — | HMAC signing secret from your Root webhook subscription |
| `root_api_key` | **Yes** | — | Root API key for pulling images from the Root registry |
| `log_retention_days` | No | `14` | CloudWatch log retention in days |

### Outputs

| Output | Description |
|--------|-------------|
| `webhook_url` | Lambda Function URL — paste this into Root's webhook settings |
| `ecr_repository_url` | ECR repository where mirrored images are pushed |

## What Gets Deployed

```
┌─ AWS Account ────────────────────────────────────────────────┐
│                                                              │
│  Lambda Function        root-ecr-mirror                      │
│  ├─ Function URL        https://xxxxx.lambda-url...on.aws/   │
│  ├─ IAM Role            ECR push + Secrets Manager read      │
│  └─ CloudWatch Logs     /aws/lambda/root-ecr-mirror          │
│                                                              │
│  Secrets Manager                                             │
│  ├─ root-ecr-mirror/webhook-signing-secret                   │
│  └─ root-ecr-mirror/root-api-key                             │
│                                                              │
│  ECR Repository         root-mirror/                         │
│  └─ (sub-repos created automatically per image)              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Security

| Protection | How |
|-----------|-----|
| **Signature verification** | Every webhook is verified against HMAC-SHA256 ([Standard Webhooks](https://www.standardwebhooks.com/) spec) |
| **Replay protection** | Requests with timestamps older than 5 minutes are rejected |
| **No long-lived credentials** | ECR auth via IAM role; secrets in Secrets Manager |
| **Minimal IAM** | Lambda can only push to its target ECR repo and read its two secrets |
| **Timing-safe comparison** | HMAC verified with `hmac.Equal` to prevent timing attacks |
| **Event filtering** | Only `io.root.cr.image.created.v1` events are processed |

## Development

Run the tests:

```sh
go test -v ./...
```

Build locally:

```sh
go build -o ecr-mirror-lambda .
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

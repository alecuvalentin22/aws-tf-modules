output "rest_api_id" {
  description = "ID of the private REST API."
  value       = aws_api_gateway_rest_api.this.id
}

output "rest_api_arn" {
  description = "ARN of the private REST API."
  value       = aws_api_gateway_rest_api.this.arn
}

output "execute_api_endpoint_id" {
  description = "Interface endpoint the API is reachable through, whether created here or supplied."
  value       = local.endpoint_id
}

output "api_resource_policy_json" {
  description = <<-EOT
    The rendered API resource policy. Exposed so it can be asserted on in tests and read
    in review: this policy is the only thing preventing another VPC endpoint in the
    account from calling the API, and it is not legible in a plan diff.
  EOT
  value       = local.api_policy
}

output "private_domain_name_id" {
  description = <<-EOT
    The private custom domain name the hostname resolves to, whether created here or
    supplied. Needed to map further stages onto the same hostname.
  EOT
  value       = var.create_private_domain_name ? aws_api_gateway_domain_name.private[0].domain_name_id : var.private_domain_name_id
}

output "private_hosted_zone_id" {
  description = "Private hosted zone serving the hostname inside the VPC."
  value       = local.private_zone_id
}

output "cloudfront_distribution_id" {
  description = "Distribution ID, or null when exposure is \"internal\"."
  value       = local.create_distribution ? aws_cloudfront_distribution.this[0].id : null
}

output "cloudfront_domain_name" {
  description = "Distribution domain name, or null when exposure is \"internal\"."
  value       = local.create_distribution ? aws_cloudfront_distribution.this[0].domain_name : null
}

output "effective_routing" {
  description = <<-EOT
    The routing table as CloudFront will evaluate it, in order, with the origin each
    pattern resolves to. Worth putting in a change record: first-match-wins ordering is
    the part of this configuration most often misread from the Terraform.
  EOT
  value       = local.effective_routing_preview
}

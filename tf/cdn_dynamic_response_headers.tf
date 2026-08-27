locals {
  custom_responce_headers_policy = { for k, v in local.cdn_env_map : k => v.cdn.custom_responce_headers_policy if length(lookup(v.cdn, "custom_responce_headers_policy", {})) > 0 }
}

resource "aws_cloudfront_response_headers_policy" "custom_responce_headers_policy" {
  for_each = local.custom_responce_headers_policy
  name     = "${each.key}-custom_responce_headers_policy"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = lookup(each.value, "strict_transport_security", null) != null ? lookup(each.value.strict_transport_security, "access_control_max_age_sec", 31536000) : 31536000
      include_subdomains         = lookup(each.value, "strict_transport_security", null) != null ? lookup(each.value.strict_transport_security, "include_subdomains", true) : true
      preload                    = lookup(each.value, "strict_transport_security", null) != null ? lookup(each.value.strict_transport_security, "preload", null) : null
      override                   = true
    }
    dynamic "content_security_policy" {
      for_each = lookup(each.value, "content_security_policy", null) != null ? [each.value.content_security_policy] : []
      content {
        content_security_policy = content_security_policy.value
        override                = true
      }
    }

    dynamic "xss_protection" {
      for_each = lookup(each.value, "xss_protection", null) != null ? [each.value.xss_protection] : []
      content {
        mode_block = lookup(xss_protection.value, "mode_block", false)
        protection = lookup(xss_protection.value, "protection", false)
        report_uri = lookup(xss_protection.value, "report_uri", null)
        override   = true
      }
    }

    dynamic "frame_options" {
      for_each = lookup(each.value, "frame_options", null) != null ? [each.value.frame_options] : []
      content {
        frame_option = lookup(frame_options.value, "frame_option", "SAMEORIGIN")
        override   = true
      }
    }

    dynamic "content_type_options" {
      for_each = lookup(each.value, "content_type_options", null) != null ? [each.value.content_type_options] : []
      content {
         override = true
      }
    }
    

  }


  dynamic custom_headers_config {

    for_each = lookup(each.value, "custom_headers", null) != null ? [each.value.custom_headers] : []

    content{
    dynamic "items" {
      for_each = lookup(each.value, "custom_headers", null) != null ? [each.value.custom_headers.cache-control] : []
      content{
      header   = "cache-control"
      override = true
      value    = items.value
      }
    }
    dynamic "items" {
      for_each = lookup(each.value, "custom_headers", null) != null ? [each.value.custom_headers.pragma] : []
      content{
      header   = "pragma"
      override = true
      value    = items.value
      }
    }
    }
  } 

}

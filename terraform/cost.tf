# ==================================================================
# Optional monthly Cost Management budget on the TEST subscription, with email
# alerts at 80% and 100%. Created ONLY when budget_monthly_amount is set (default
# null -> nothing), so the default deploy is unaffected. [SECURITY.md M-6]
# ==================================================================
data "azurerm_subscription" "current" {
  count = var.budget_monthly_amount != null ? 1 : 0
}

# Stable month anchor for the budget start (first of the creation month),
# persisted in state so it does not drift on re-apply.
resource "time_static" "budget" {
  count = var.budget_monthly_amount != null ? 1 : 0
}

resource "azurerm_consumption_budget_subscription" "lab" {
  count           = var.budget_monthly_amount != null ? 1 : 0
  name            = "${var.lab_prefix}-budget"
  subscription_id = data.azurerm_subscription.current[0].id
  amount          = var.budget_monthly_amount
  time_grain      = "Monthly"

  time_period {
    start_date = "${formatdate("YYYY-MM", time_static.budget[0].rfc3339)}-01T00:00:00Z"
    end_date   = "2035-12-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    contact_emails = var.budget_alert_emails
  }

  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThan"
    contact_emails = var.budget_alert_emails
  }

  lifecycle {
    precondition {
      condition     = var.budget_monthly_amount == null || length(var.budget_alert_emails) > 0
      error_message = "budget_monthly_amount is set but budget_alert_emails is empty: add at least one email to receive the alerts."
    }
  }
}

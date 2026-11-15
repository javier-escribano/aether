variable "lab_prefix" {
  type = string
}

variable "tenant_domain" {
  type = string
}

variable "user_count" {
  type    = number
  default = 5
}

variable "enable_ap01" {
  type    = bool
  default = false
}

variable "enable_ap03" {
  type    = bool
  default = false
}

variable "enable_ap04" {
  type    = bool
  default = false
}

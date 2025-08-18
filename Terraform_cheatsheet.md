# Terraform cheatsheet

## Basic commands

**`terraform init`**
Initialize the directory by downloading all needed providers (plugins)

**`terraform init -update`**
Update existing and install additional needed providers after changing the Terraform code

**`terraform plan`**
Show planned actions - do not apply them (dryrun)

**`terraform apply`**
Execute the code and apply all changes to the infrastructure

**`terraform apply -refresh=false`**
Execute the code and apply all changes to the infrastructure without checking the actual state of the infrastructure but only relaying on the state file (*terraform.tfstate*)

**`terraform validate`**
Validate all Terraform-files and check if the syntax is correct

**`terraform fmt`**
Format all Terraform-files according to the Terraform code style

**`terraform show`**
Print currecnt state of the infrastructure

**`terraform show -json`**
Print currecnt state of the infrastructure in JSON format

**`terraform providers`**
Show providers used in the project

**`terraform output`**
Show outputs of the actual status

**`terraform graph`**
Output of a graph, whoch can be read by some tools - e.g.:
`terraform graph | dot -Tsvg > graph.svg`


## Useage examples

### Provider version constrains

```hcl
terraform {
  required_providers {
    local = {
      version = "2.5.3"
      source  = "hashicorp/local"
    }
    random = {
      version = "!= 3.7.0"                   # Not 3.7.0
      source  = "hashicorp/random"
    }
    http = {
      version = "> 3.0.0, < 4.0.0, != 3.4.5" # Between 3.0.0 and 4.0.0 but not 3.4.5
      source  = "hashicorp/http"
    }
  }
}
```

### Variables and simple ressource creation using Terraform

```hcl
# Define a variable
variable "output_folder" {
  type    = string
  default = "D:/Terraform/output"
}

resource "local_file" "sample_file" {
  filename = "${var.output_folder}/sample_file.txt"          # Use the variable defined above
  content  = "This is a sample file created by Terraform."
}
```

### Random string, ressource references and sensitive file creation

```hcl
# Random string resource to generate a password
resource "random_string" "password" {
  length  = 16
  special = true
}

# Sensitive file - does not show content in plan or apply
resource "local_sensitive_file" "password_file" {
  content  = "The password is: ${random_string.password.result}" # Accessing the result of the random_string resource via resource reference
  filename = "${var.output_folder}/password.txt"                 # Use the variable defined above
}
```

### Random string, variables, ressource references and sensitive file creation

```hcl
# Random integer resource - stored in the state file
resource "random_integer" "rand_int" {
  min = 1
  max = 100
}

# Output the results to the screen
output "rand_int_value" {
  value = random_integer.rand_int.id
}
```

### Data sources, functions and lifecycle management

```hcl
# Read data from the internet
data "http" "example" {
  url = "https://ipinfo.io/8.8.8.8/json"
}

# Pasre the JSON response with the jsondecode function 
locals {
  ip_info = jsondecode(data.http.example.response_body)
}

# Ressource with lifecycle management information
resource "local_file" "ip_info" {
  content         = "IP-LOCATION: ${local.ip_info.region} (${local.ip_info.country})" # Use the parsed JSON data to get the country code
  filename        = "${var.output_folder}/ip_info.txt"
  file_permission = "0644"

  lifecycle {
    ignore_changes        = [file_permission] # Ignore changes in file permissions to prevent unnecessary updates
    create_before_destroy = false             # Create new ressource before destroying the old one - true can be uses for servers to prevent interrupting the service, does not work with local files
    prevent_destroy       = true              # Prevent the resource from being destroyed accidentally
  }
}
```

### Calculations and loops in Terraform

```hcl
# Calculate rand_int modulo 3 and store in a local variable
locals {
  no_of_files = random_integer.rand_int.id % 3
}

# Create no_of_files local files with a loop
resource "local_file" "loop_sample" {
  count    = local.no_of_files
  content  = "This is file number ${count.index + 1}."
  filename = "${var.output_folder}/loop_file_${count.index + 1}.txt"
}

# Define a list and loop through it to create files with different names
# Drawback of that method is, that the ressources are stored in a list in the state file
# Deleting the 2nd element would case the deletion of elements 2ne and 3rd element and 
# the re-creation of the old element 3rd element as 2nd element
variable "files_to_create" {
  default = [
    "loop_file_A.txt",
    "loop_file_B.txt",
    "loop_file_C.txt"
  ]
}
resource "local_file" "loop_sample_2" {
  count    = length(var.files_to_create)
  content  = "This is file number ${count.index + 1}."
  filename = "${var.output_folder}/${var.files_to_create[count.index]}" # Use the variable defined above to create files with different names
}

# Foreach - does not have the same drawback as the count method
variable "files_to_create_2" {
  default = [
    "loop_file_D.txt",
    "loop_file_E.txt"
  ]
}
resource "local_file" "loop_sample_3" {
  for_each = toset(var.files_to_create_2)         # does mit work with a list, toset() converts list to set
  filename = "${var.output_folder}/${each.value}" # Use the key from the set to create files with different names
  content  = "This is file ${each.value}."
}
```

### Specifying credentials to access cloud ressources

```hcl
provider "azurerm" {
  subscription_id = "00000000-0000-0000-0000-000000000000"
  client_id       = "11111111-1111-1111-1111-111111111111"
  client_secret   = "your-client-secret"                    # Only for demonstration - hardcoding cedentials is uncool!!!
  tenant_id       = "22222222-2222-2222-2222-222222222222"
}

provider "aws" {
    region     = "us-west-2"
    access_key = "SAMPLEKEY"
    secret_key = "SAMPLESAMPLE/KEY/SAMPLESAMPLE"  # Only for demonstration - hardcoding cedentials is uncool!!!
}

provider "google" {
  project     = "your-gcp-project-id"
  region      = "us-central1"
  credendials = "keys.json"  # Do not include that file to the repo to prevent credential leaking!!!
}
```

Better approach is 

 - exporting environment variables  
   ```bash
   export ARM_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
   export ARM_CLIENT_ID="11111111-1111-1111-1111-111111111111"
   export ARM_CLIENT_SECRET="your-client-secret"
   export ARM_TENANT_ID="22222222-2222-2222-2222-222222222222"
   ```  
   and using that in Terraform by:  
   ```hcl
   provider "azurerm" {
     features {}
   }
   ```
 - storing the credentials in the AWS - credentials file (`~/.aws/credentials`) by running `aws configure` and then Terraform will use the credentials stored in this file.
 - 

### Working with the cloud and providing references to pevious created objects

```hcl
# Create user
resource "aws_iam_user" "mark" {
    name = "mark.b"
    tags = {
      Description = "New team member"
    }
}

# Create policy (load policy from external file)
resource "aws_iam_policy" "admin_user" {
  name = "AdminUser"
  policy = file("policies/admin_access_policy.json")
}

# Load data for existing elements from AWS
data "aws_iam_group" "finance_analyst_group" {
  group_name = "finance-analysts"
}

# Create S3 bucket
resource "aws_s3_bucket" "finance_data_bucket" {
  bucket = "megacorp-secret-finance-data-123456"
}

# Create policy (policy in heredoc)
resource "aws_iam_policy" "finance_bucket_access" {
  bucket = aws_s3_bucket.finance_data_bucket.id
  policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "arn:aws:s3:::${aws_s3_bucket.finance_data_bucket.id}/*",
        "Principal": {
            "AWS": [
                "${data.aws_iam_group.finance_analyst_group.arn}"
            ]
        }
      }
    ]
  }
  EOF
}

# Attach policy arn (AWS resource number) to user 
resource "aws_iam_user_policy_attachment" "admin-access-for-mark" {
  user = aws_iam_user.mark.name
  policy_arn = aws_iam_policy.admin_user.arn
}

# Upload a file
resource "aws_s3_object" "upload" {
  bucket = aws_s3_bucket.finance_data_bucket.bucket
  key    = "annual_report_2025.pdf"
  source = "/home/someuser/annual_report_2025_FINAL_VERSION_AFTER_TAX_OPTIMISATION.pdf"
}
```

Using heredoc to add the policy "inline" allows also the use of variables in the policy, which is not possible when loading a policy from a file!

``

##

```hcl

```

##

```hcl

```
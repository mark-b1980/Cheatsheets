# Terraform cheatsheet

## Basic commands

| Command                                          | Description                                                                                                                      |
|--------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `terraform init`                                 | Initialize the directory by downloading all needed providers (plugins)                                                           |
| `terraform init -update`                         | Update existing and install additional needed providers after changing the Terraform code                                        |
| `terraform plan`                                 | Show planned actions - do not apply them (dry run)                                                                               |
| `terraform apply`                                | Execute the code and apply all changes to the infrastructure                                                                     |
| `terraform apply -replace <RESOURCE>`            | Forced recreation of a speciffic resource                                                                                        |
| `terraform apply -refresh=false`                 | Apply changes without checking the actual infrastructure state, relying only on the state file                                   |
| `terraform apply -target <RESOURCE>`             | Apply changes only to a speciffic resource - e.g.: `random_string.suffix`                                                        |
| `terraform validate`                             | Validate all Terraform files and check if the syntax is correct                                                                  |
| `terraform fmt`                                  | Format all Terraform files according to the Terraform code style                                                                 |
| `terraform show`                                 | Print current state of the infrastructure                                                                                        |
| `terraform show -json`                           | Print current state of the infrastructure in JSON format                                                                         |
| `terraform providers`                            | Show providers used in the project                                                                                               |
| `terraform output`                               | Show outputs of the actual status (does not display sensitive variables)                                                         |
| `terraform output <VARIABLENAME>`                | Show output of a specific variable (also displays sensitive variables)                                                           |
| `terraform graph`                                | Output a graph (can be processed by tools, e.g. `terraform graph \| dot -Tsvg > graph.svg`)                                      |
| `terraform state list`                           | List all resources in the state file                                                                                             |
| `terraform state show <RESOURCENAME>`            | Show all state information for one specific resource                                                                             |
| `terraform state mv <SOURCE> <DESTINATION>`      | Rename a resource or move it between state files (prevents recreation if renamed in both state file and code)                    |
| `terraform state pull`                           | Get the actual state file from a remote location                                                                                 |
| `terraform state rm <RESOURCENAME>`              | Remove a resource from the state file (removes from management without destroying; will be recreated if not removed from code)   |
| `terraform taint <RESOURCENAME>`                 | Mark a resource for recreation (taint)                                                                                           |
| `terraform untaint <RESOURCENAME>`               | Remove taint from a resource                                                                                                     |
| `terraform workspace list`                       | List all workspaces                                                                                                              |
| `terraform workspace new <WORKSPACENAME>`        | Create a new workspace                                                                                                           |
| `terraform workspace select <WORKSPACENAME>`     | Switch to a specific workspace                                                                                                   |


## Typical files 

| File               | Purpose                                                                                      |
|--------------------|----------------------------------------------------------------------------------------------|
| `main.tf`          | Main file in the project                                                                     |
| `outputs.tf`       | Defines outputs from resources                                                               |
| `provider.tf`      | Provider settings (e.g., AWS region)                                                         |
| `terraform.tf`     | Terraform configuration (provider versions, remote state location, etc.)                     |
| `terraform.tfvars` | Variable values (e.g., `ami="ami-xxxxxxxxx"`)                                                |
| `variables.tf`     | Variable definitions (e.g., `variable "ami" { ... }`)                                        |


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

---

### Variables and simple ressource creation using Terraform

```hcl
# Define a variable - if there is no value defined Terraform ask for a value when running apply
variable "output_folder" {
  type        = string                 # Could be also bool, number, set(...), list(...), map(...) or tuple(...)
  default     = "D:/Terraform/output"  # If not specified will be taken from env. variable, .tfvars file or CLI argument
  description = "Additional infos"     # Printed when prompted to enter a value interactivly 
  sensitive   = true                   # Suppress the output of the value on screen
  validation  = {
    condition     = substr(var.output_folder, 0, 2) == "D:"
    error_message = "Only folders on D:\ are allowed!"
  }
}

resource "local_file" "sample_file" {
  filename = "${var.output_folder}/sample_file.txt"          # Use the variable defined above
  content  = "This is a sample file created by Terraform."
}

# Data structres with object variables
variable "textfile" {
  type = object({
    filename  = string
    content   = string
    version   = number
    sensitive = bool
  })

  default = {
    filename  = "D:/Terraform/output/file2.txt"
    content   = "This is the file content"
    version   = 1
    sensitive = false
  }
}

resource "local_file" "name" {
  filename = var.textfile.filename
  content  = var.textfile.content
}
```

---

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

---

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

---

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

---

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

### Provider alias

```hcl
provider "aws" {
  region = "eu-west-1" 
}

provider "aws" {
  alias  = "west2"
  region = "eu-west-2"
}

# Use default aws provider for resources in eu-west-1
resource "aws_key_pair" "eu_key_1" {
  key_name = "eu_key_1"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCy..."
}

# Use aliased aws provider for resources in eu-west-2
resource "aws_key_pair" "eu_key_2" {
  provider = aws.west2
  key_name = "eu_key_2"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCy..."
}
```

---

### Specifying credentials to access cloud ressources

```hcl
provider "azurerm" {
  subscription_id = "00000000-0000-0000-0000-000000000000"
  client_id       = "11111111-1111-1111-1111-111111111111"
  client_secret   = "your-client-secret"                    # Only for demonstration - hardcoding cedentials is uncool!!!
  tenant_id       = "22222222-2222-2222-2222-222222222222"
}

provider "aws" {
    region     = "eu-west-2"
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

---

### Working with the cloud and providing references to pevious created objects

**AWS example**

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
  user       = aws_iam_user.mark.name
  policy_arn = aws_iam_policy.admin_user.arn
}

# Upload a file
resource "aws_s3_object" "upload" {
  bucket = aws_s3_bucket.finance_data_bucket.bucket
  key    = "annual_report_2025.pdf"
  source = "/home/someuser/annual_report_2025_FINAL_VERSION_AFTER_TAX_OPTIMISATION.pdf"
}

# Creating a table
resource "aws_dynamodb_table" "todo_list" {
  name         = "todo_list"
  hash_key     = "id" # primary key
  billing_mode = "PAY_BY_REQUEST"
  attribute {
    name = "id"
    type = "N" # number
  }
}

# Adding one entry: S = string, N = number, B =  binary
resource "aws_dynamodb_table_item" "todo_entries" {
  table_name = aws_dynamodb_table.todo_list.name
  hash_key   = aws_dynamodb_table.todo_list.hash_key
  item       = <<EOF
  {
  "id": {"N": "1" },
  "entry": {"S": "Setup new server with Rocky Linux 8"}
  }
  EOF
}

# Managing multiple entries in a loop
locals {
  todo_entries = {
    "1" = {
      entry = "Setup new server with Rocky Linux 8"
    },
    "2" = {
      entry = "Finnish Terraform cheatsheet"
    },
    "3" = {
      entry = "Buy new hacking gadgets"
    }
  }
}
resource "aws_dynamodb_table_item" "todo_entries" {
  for_each   = local.todo_entries
  table_name = aws_dynamodb_table.todo_list.name
  hash_key   = aws_dynamodb_table.todo_list.hash_key
  item       = jsonencode({
    "id" : { N = each.key },
    "entry" : { S = each.value.entry }
  })
}

# Public key
resource "aws_key_pair" "webserver_keys" {
  public_key = file("/home/someuser/webserver01.pub")
  key_name   = "webserver01_key"
}

# Security group to allow access via SSH
resource "aws_security_group" "allow_ssh_ingress" {
  name        = "ssh-access"
  description = "Allow SSH access from everywhere"
  ingress = {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 instance (using AWS speciffic user_data for initial setup)
resource "aws_instance" "webserver01" {
  ami           = "ami-abcdef1234567890" # AWS machine image ID
  instance_type = "t2.micro"
  tags = {
    Name = "NGINX webserver 01"
  }
  key_name               = aws_key_pair.webserver_keys.id
  vpc_security_group_ids = [aws_security_group.allow_ssh_ingress.id]
  user_data              = <<EOF
  #!/bin/bash
  sudo apt update
  sudo apt install nginx
  systemctl enable nginx
  systemctl start nginx
  EOF
}

# EC2 instance (using provisioner for initial setup - universal)
resource "aws_instance" "webserver01" {
  ami           = "ami-abcdef1234567890" # AWS machine image ID
  instance_type = "t2.micro"
  tags = {
    Name = "NGINX webserver 01"
  }
  key_name               = aws_key_pair.webserver_keys.id
  vpc_security_group_ids = [aws_security_group.allow_ssh_ingress.id]
  # Setup
  provisioner "remote-exec" {
    inline = [
      "sudo apt update",
      "sudo apt install nginx",
      "systemctl enable nginx",
      "systemctl start nginx"
    ]
  }
  # Setup connection
  connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ubuntu"
    private_key = file("/home/someuser/webserver01.pub")
  }
  # Saving the webserver IP in a file
  provisioner "local-exec"{
    command = "echo ${aws_instance.webserver01-public_ip} > /home/someuser/webserver01_ip.txt"
  }
  # Removing the webserver IP file
  provisioner "local-exec"{
    when       = destroy   # Run only on destroy
    on_failure = continue  # Ignore errors in the provisioner execution and continue
    command    = "rm /home/someuser/webserver01_ip.txt"
  }
}

# Elastic IP (static IP for the server)
resource "aws_eip" "eip" {
  vpc      = true
  instance = aws_instance.webserver01.id
}

# Display webservers public IP
output "webserver01_ip" {
  value = aws_instance.webserver01.public_ip
}
```

Using heredoc to add the policy "inline" allows also the use of variables in the policy, which is not possible when loading a policy from a file!

Use provisioners rarely or as a last resort option. Provisioners can run any system command and thatfor Terraform has no way to model the provisioner outcome in its plan! Rather use

 - `custom_data` for Azure `azurerm_virtual_machine`
 - `user_data` for AWS `aws_instance`
 - `meta_data` for GCP `google_compute_instance`
 - `user_data.txt` for VMWare `vsphere_virtual_machine`

Or use custom images - e.g. created with [Packer](https://developer.hashicorp.com/packer)

---

### Creating reusable blocks with locals

```hcl
# Creating a local definition block
locals {
  proj_a_tags = {
    Department  = "IT"
    Project     = "Project A"
    CostNumber  = 10001
    SystemOwner = "Mark B."
  }
}

# Creating various ressources using the same tags
resource "aws_key_pair" "eu_key_1" {
  key_name   = "proj_a_key_1"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCy..."
  tags       = locals.proj_a_tags
}
resource "aws_s3_bucket" "proj_a_bucket" {
  bucket = "megacorp-proj-a-data-123456"
  tags   = locals.proj_a_tags
}
resource "aws_dynamodb_table" "proj_a_db" {
  name         = "proj_a_db"
  hash_key     = "id"
  billing_mode = "PAY_BY_REQUEST"
  attribute {
    name = "id"
    type = "N" 
  }
  tags         = locals.proj_a_tags
}
...
```

---

### Dynamic blocks

**varibles.tf**

```hcl
variable "ingress_ports" {
  default = [22, 80, 443]
}
```

**main.tf**

```hcl
resource "aws_security_group" "allow_ingress_ports" {
  name        = "allow-ingress-access"
  description = "Allow SSH, HTTP and HTTPS access from everywhere"
  dynamic "ingress" {
    for_each    = var.ingress_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
```

---

### Remote state file for cooperating in a team

```hcl
# Azure (state locking handled by the bucket)
terraform {
  backend "azurerm" {
    resource_group_name  = "tfstate"
    storage_account_name = "tfstateblobuser"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }
}

# AWS (state locking handled by dynamo db)
terraform {
  backend "s3"{
    bucket         = "some-name-remote-state-file-001"
    key            = "terraform.tfstate"
    region         = "eu-west-2"
    dynamodb_table = "state_locking_table"
  }
}
resource "aws_dynamodb_table" "terraform_state_locking" {
  name         = "state_locking_table" # Needed for locking
  billing_mode = "PAY_BY_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}

# GCP (state locking handled by the bucket)
terraform {
  backend "gcs" {
    bucket = "some-name-remote-state-file-001"  # filename "terraform.tfstate" is implicitly used
  }
}
```

... needed to prevent team members running `apply` commands simultanious and creating inconsistant states. 

---

### Import, Taint and Debugging

Activate logging by running the following commands before executing a Terraform command:

```bash
export TF_LOG="TRACE"
export TF_LOG_PATH="/tmp/terraform.log"
```

Whenever a command fail during `apply` the resource for which the command has failed become "tainted", which means it is maked for recreation on the next `apply`! We can use that to force a recreation of a resouce with the `terraform taint` command or remove a taint with the `terraform untaint` command...

Before importing a resource create at least an empty ressource block:

```hcl
resource "aws_instance" "webserver01" {

}
```

Importing of the ressource can be done with `terraform import <PROVIDER>.<NAME> <RESOURCEID>` - e.g.:

```bash
terraform import aws_instance.webserver01 i-e6b23a77ea713f01c
```

---

### Modules

Modules man be used to create reusable code and to ensure consitency across multiple instances. 

Thatfor we can create the `my-webapp-v2` subdiretory in the `modules` folder which contain multiple files:

**app_server.tf**

```hcl
resource "aws_instance" "app_server" {
  ami           = var.ami    # Value will be dynamically provided when using 
  instance_type = "t2.micro" # Hardcoded and not configurable
  tags = {
    Name = "NGINX webserver in ${var.app_region}"
  }
  depends_on    = [aws_dynamodb_table.app_db, aws_s3_bucket.app_bucket]
}
```

**app_bucket.tf**

```hcl
resource "aws_s3_bucket" "app_bucket" {
  bucket = "${var.app_region}-${var.bucket}"
}
```

**app_table.tf**

```hcl
resource "aws_dynamodb_table" "app_db" {
  name         = "app_data"
  hash_key     = "id"
  billing_mode = "PAY_BY_REQUEST"
  attribute {
    name = "id"
    type = "N" 
  }
}
```

**variables.tf**

```hcl
variable "app_region"{
  type = string # Will be specified when using
}
variable "baucket"{
  default = "my-webapp-v2-1" # Default for all instances the same
}
variable "ami"{
  type = string
}
```

After this modules can be used in a Terraform file...

**app_deploment_eu.tf**

```hcl
# Use the module
module = {
  source     = "modules/my-webapp-v2"
  app_region = "eu-west-2"
  ami        = "ami-abcdef1234567890"
}

# Display public IP (note the "module.my-webapp-v2" prefix)
output "webserver01_ip" {
  value = module.my-webapp-v2.aws_instance.app_server.public_ip
}
```

Terraform comes also with a whole library of modules ready to use. Those can be used as follows:

```hcl
module "security-group-ssh-ingress" {
  source              = "terraform-aws-modules/security-group/aws/modules/ssh"
  version             = "3.16.0"
  vpc_id              = "vpc-7d78d15"
  name                = "allow-ssh-ingress-from-subnet"
  ingress_cidr_blocks = ["10.0.0.0/24"]
}
```

---

### Workspaces

... can be used to re-use the same code for different locations, scenarios, etc.

**varibles.tf**

```hcl
variable "region" {
  default = "eu-west-1"
}
variable "type" {
  default = "t2.micro"
}
variable "ami" {
  default = {
    "ProjectA" = "ami-abcdef1234567890"
    "ProjectB" = "ami-0987654321abcdef"
  }
}
```

**main.tf**

```hcl
resource "aws_instance" "app_server" {
  ami           = lookup(var.ami, terraform.workspace) # get the correct AMI for the workspace
  instance_type = var.type
  tags = {
    Name = "${var.region} Server"
  }
}
```

Depending on the workflow (ProjectA or ProjectB) the same server but with a different AMI is created.

---

### Functions

To test the build-in functions I have crated a variable.tf file with those variables:

```hcl
variable "l" {
  default = [1, 3, 5, -1, -3, -5]
}

variable "s" {
  default = "I am a string"
}

variable "l2" {
  type    = "list"
  default = ["a", "b", "c", "a", "d"]
}

variable "m" {
  type    = "map"
  default = {
    "a" = "Ansible"
    "p" = "Python"
    "t" = "Terraform"
  }
}
```

And used then the interactive console (`terraform console`):

```bash
> min(var.l...)
-5
> max(var.l...)
5
> ceil(1.9)
2
> floor(1.9)
1

> split(" ", var.s)
tolist([
  "I",
  "am",
  "a",
  "string",
])
> lower(var.s)
"i am a string"
> upper(var.s)
"I AM A STRING"
> title(var.s)
"I Am A String"
> substr(var.s, 0, 4)
"I am"
> substr(var.s, 7, 6)
"string"

> length(var.l2)
5
> index(var.l2, "c")
2
> contains(var.l2, "d")
true
> element(var.l2, 1)
"b"
> toset(var.l2)
toset([
  "a",
  "b",
  "c",
  "d",
])

> keys(var.m)
tolist([
  "a",
  "p",
  "t",
])
> values(var.m)
tolist([
  "Ansible",
  "Python",
  "Terraform",
])
> lookup(var.m, "t")
"Terraform"
> lookup(var.m, "x", "dafault-value-if-no-entry-found")
"dafault-value-if-no-entry-found"
> lookup(var.m, "x")
╷
│ Error: Error in function call
│
│   on <console-input> line 1:
│   (source code not available)
│
│ Call to function "lookup" failed: lookup failed to find key "x".
╵
```

Here we use `...` to access the contents of the list instread of the list as a whole. Needed e.g. for `min()`, which require one or multiple numbers as input but not a list of numbers!

**Operators**

```bash
> (6+2)/4
2
> "8" == 8
false
> 3 == 3
true
> 1 < 8
true
> !(3 == 3)
false
> 3 == 3 && 4 != 5
true
> 3 == 4 || "b" == "b"
true
```

**Using functions and expressions in Terraform**

```hcl
resource "random_string" "new_password" {
  length = var.pw_length < 8 ? 8 : var.pw_length # enforce min. length of 8 characters
}

variable "pw_length" {
  type = number
  description = "Length of the new generated password"
}

output "new_password" {
  value = random_string.new_password.result
}
```

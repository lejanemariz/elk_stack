terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.36.0"
    }
  }
}

provider "aws" {
    region = "us-west-2"
    access_key = "AKIAVJQ42LGRCYCVKPE5"
    secret_key = "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"
}

 resource "aws_security_group" "terraform-sg" {
   name        = "jane36b-sg2"
   description = "Allow TLS inbound traffic"

   ingress {
     description      = "SSH"
     from_port        = 22
     to_port          = 22
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "ElasticSearch"
     from_port        = 9200
     to_port          = 9200
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "ElasticSearch2"
     from_port        = 9300
     to_port          = 9300
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "InfluxDB"
     from_port        = 8086
     to_port          = 8086
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "HCP"
     from_port        = 8200
     to_port          = 8200
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "Grafana"
     from_port        = 3000
     to_port          = 3000
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "Jenkins"
     from_port        = 8080
     to_port          = 8080
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "Kibana"
     from_port        = 5601
     to_port          = 5601
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   ingress {
     description      = "Logstash"
     from_port        = 5000
     to_port          = 5000
     protocol         = "tcp"
     cidr_blocks      = ["0.0.0.0/0"]
   }

   egress {
     from_port        = 0
     to_port          = 0
     protocol         = "-1"
     cidr_blocks      = ["0.0.0.0/0"]
     ipv6_cidr_blocks = ["::/0"]
   }

   tags = {
     Name = "allow_tls"
   }
}

resource "aws_instance" "web_micro" {
    count = 3
    ami           = "ami-017fecd1353bcc96e"
    instance_type = "t2.micro"
    key_name      = "jane36b-key"
    security_groups = [aws_security_group.terraform-sg.name]

    tags = {
        Name = "jane36b-${count.index}"
    }
}

resource "local_file" "instance_public_DNS" {
  content  = yamlencode({"ansible_host_ip": aws_instance.web_micro[*].public_ip})
  filename = "host_ip.yml"
}



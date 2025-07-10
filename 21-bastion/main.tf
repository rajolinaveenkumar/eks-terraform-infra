resource "aws_instance" "this" {

    ami = data.aws_ami.rhel9.id
    instance_type = local.instance_type
    vpc_security_group_ids = [data.aws_ssm_parameter.bastion_sg_id.value]
    subnet_id = local.public_subnet_id


  # 20GB is not enough
  root_block_device {
    volume_size = 50  # Set root volume size to 50GB
    volume_type = "gp3"  # Use gp3 for better performance (optional)
  }
  user_data = file("bastion.sh")

 
     tags = merge(
        
        var.common_tags,
        {
            Name            =  "${local.server_name}"
            Owner    =  "Naveen Rajoli"
            Terraform       = true
        }
    )


}

output "bastion_ip" {
  value = aws_instance.this.public_ip
}


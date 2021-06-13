cd infra
export ANSIBLE_CONFIG=ansible.cfg
./upload-bin-genesis.sh
ansible-playbook provision-ec2-mumbai.yml
sleep 120
rm -rf /tmp/aws_inventory
ansible-playbook deploy-nodes.yml
sleep 120
ansible-playbook set-keys.yml
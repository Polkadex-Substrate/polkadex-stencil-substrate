cd infra || exit
export ANSIBLE_CONFIG=ansible.cfg
./upload-bin-genesis.sh
ansible-playbook restart.yml
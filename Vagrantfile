# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  config.vm.box = "ubuntu/trusty64"

  config.vm.network "private_network", ip: "192.168.50.127"

  config.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
  end

  config.vm.provision "shell", path:"bootstrap/bootstrap-dev-admin.sh", privileged:true, binary: false

  config.vm.provision "shell", path:"bootstrap/bootstrap-dev.sh", privileged:false, binary: false

end

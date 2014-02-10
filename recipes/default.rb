#
# Cookbook Name:: tomcat
# Recipe:: default
#
# Copyright 2010, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# required for the secure_password method from the openssl cookbook
::Chef::Recipe.send(:include, Opscode::OpenSSL::Password)

include_recipe "java"

tomcat_pkgs = value_for_platform(
  ["debian","ubuntu"] => {
    "default" => ["tomcat#{node["tomcat"]["base_version"]}","tomcat#{node["tomcat"]["base_version"]}-admin"]
  },
  ["centos","redhat","fedora","amazon"] => {
    "default" => ["tomcat#{node["tomcat"]["base_version"]}","tomcat#{node["tomcat"]["base_version"]}-admin-webapps"]
  },
  ["smartos"] => {
    "default" => ["apache-tomcat"]
  },
  "default" => ["tomcat#{node["tomcat"]["base_version"]}"]
)

tomcat_pkgs.each do |pkg|
  package pkg do
    action :install
    version node["tomcat"]["base_version"].to_s if platform_family?("smartos")
  end
end

directory node['tomcat']['endorsed_dir'] do
  mode "0755"
  recursive true
end

unless node['tomcat']['deploy_manager_apps']
  directory "#{node['tomcat']['webapp_dir']}/manager" do
    action :delete
    recursive true
  end
  file "#{node['tomcat']['config_dir']}/Catalina/localhost/manager.xml" do
    action :delete
  end
  directory "#{node['tomcat']['webapp_dir']}/host-manager" do
    action :delete
    recursive true
  end
  file "#{node['tomcat']['config_dir']}/Catalina/localhost/host-manager.xml" do
    action :delete
  end
end

case node["platform"]
when "smartos"
  template "/opt/local/share/smf/apache-tomcat/manifest.xml" do
    source "manifest.xml.erb"
    owner "root"
    group "root"
    mode "0644"
    notifies :run, "execute[tomcat_manifest]"
  end
  execute "tomcat_manifest" do
    command "svccfg import /opt/local/share/smf/apache-tomcat/manifest.xml"
    action :nothing
    notifies :restart, "service[tomcat-blue]"
    notifies :restart, "service[tomcat-green]"
  end
end

#region Remove default resources from system package
service "tomcat" do
  case node["platform"]
  when "centos","redhat","fedora","amazon"
    service_name "tomcat#{node["tomcat"]["base_version"]}"
    supports :restart => true, :status => true
  when "debian","ubuntu"
    service_name "tomcat#{node["tomcat"]["base_version"]}"
    supports :restart => true, :reload => false, :status => true
  when "smartos"
    service_name "tomcat"
    supports :restart => true, :reload => false, :status => true
  else
    service_name "tomcat#{node["tomcat"]["base_version"]}"
  end
  action [:stop, :disable]
  retries 4
  retry_delay 30
  notifies :delete, "directory[#{node["tomcat"]["config_dir"]}]"
  notifies :delete, "directory[/var/log/tomcat6]"
  notifies :delete, "directory[/var/cache/tomcat6]"
  notifies :delete, "directory[/var/lib/tomcat6]"
  notifies :delete, "file[/etc/init.d/tomcat6]"
end

[node["tomcat"]["config_dir"], "/var/log/tomcat6", "/var/cache/tomcat6", "/var/lib/tomcat6"].each do |dir|
  directory dir do
    recursive true
    action :nothing
  end
end

file "/etc/init.d/tomcat6" do
  action :nothing
end

#endregion

node.set_unless['tomcat']['keystore_password'] = secure_password
node.set_unless['tomcat']['truststore_password'] = secure_password

unless node['tomcat']["truststore_file"].nil?
  java_options = node['tomcat']['java_options'].to_s
  java_options << " -Djavax.net.ssl.trustStore=#{node["tomcat"]["config_dir"]}/#{node["tomcat"]["truststore_file"]}"
  java_options << " -Djavax.net.ssl.trustStorePassword=#{node["tomcat"]["truststore_password"]}"

  node.set['tomcat']['java_options'] = java_options
end

#region Create resources for blue and green Tomcats
%w(blue green).each do |env|
  directory "/var/cache/tomcat6-#{env}" do
    owner node["tomcat"]["user"]
    group "adm"
    mode "0750"
  end

  directory "/var/log/tomcat6-#{env}" do
    owner node["tomcat"]["user"]
    group "adm"
    mode "0750"
  end

  directory "/var/lib/tomcat6-#{env}" do
    owner "root"
    group "root"
    mode "0755"
  end

  %W(/var/lib/tomcat6-#{env}/conf
  /var/lib/tomcat6-#{env}/conf/Catalina
  /var/lib/tomcat6-#{env}/conf/Catalina/localhost).each do |dir|
    directory dir do
      owner "root"
      group "root"
      mode "0755"
    end
  end

  directory "/var/lib/tomcat6-#{env}/webapps" do
    owner node["tomcat"]["user"]
    group node["tomcat"]["group"]
    mode "0755"
  end

  %W(/var/lib/tomcat6-#{env}/conf/Catalina/localhost/manager.xml
  /var/lib/tomcat6-#{env}/conf/catalina.properties
  /var/lib/tomcat6-#{env}/conf/context.xml
  /var/lib/tomcat6-#{env}/conf/logging.properties).each do |tpl|
    template tpl do
      owner "root"
      group "root"
      mode "0644"
      notifies :restart, "service[tomcat-#{env}]"
    end
  end

  template "/var/lib/tomcat6-#{env}/conf/server.xml" do
    source "server.xml.erb"
    owner "root"
    group "root"
    mode "0644"
    variables(
      server_port: node["tomcat"]["#{env}_server_port"],
      http_port: node["tomcat"]["#{env}_http_port"],
      https_port: node["tomcat"]["#{env}_https_port"]
    )
    notifies :restart, "service[tomcat-#{env}]"
  end

  template "/var/lib/tomcat6-#{env}/conf/web.xml" do
    owner "root"
    group "root"
    mode "0644"
    notifies :restart, "service[tomcat-#{env}]"
  end

  directory "/var/lib/tomcat6-#{env}/conf/policy.d" do
    owner "root"
    group node["tomcat"]["group"]
    mode "0755"
  end

  %W(01system.policy 02debian.policy 03catalina.policy 04webapps.policy 50local.policy ).each do |policy|
    template "/var/lib/tomcat6-#{env}/conf/policy.d/#{policy}" do
      source "policy.d_#{policy}.erb"
      owner "root"
      group node["tomcat"]["group"]
      mode "0644"
      notifies :restart, "service[tomcat-#{env}]"
    end
  end

  %w(common server shared).each do |class_group|
    directory "/var/lib/tomcat6-#{env}/#{class_group}" do
      owner node["tomcat"]["user"]
      group node["tomcat"]["group"]
      mode "0755"
    end

    directory "/var/lib/tomcat6-#{env}/#{class_group}/classes" do
      owner node["tomcat"]["user"]
      group node["tomcat"]["group"]
      mode "0755"
    end
  end

  link "/var/lib/tomcat6-#{env}/logs" do
     to "../../log/tomcat6-#{env}"
  end

  link "/var/lib/tomcat6-#{env}/work" do
    to "../../cache/tomcat6-#{env}"
  end

  case node["platform"]
  when "centos","redhat","fedora","amazon"
    template "/etc/sysconfig/tomcat#{node["tomcat"]["base_version"]}-#{env}" do
      source "sysconfig_tomcat6.erb"
      owner "root"
      group "root"
      mode "0644"
      variables(
        catalina_base: "/var/lib/tomcat6-#{env}"
      )
      notifies :restart, "service[tomcat-#{env}]"
    end
  when "smartos"
  else
    template "/etc/default/tomcat#{node["tomcat"]["base_version"]}-#{env}" do
      source "default_tomcat6.erb"
      owner "root"
      group "root"
      mode "0644"
      variables(
        catalina_base: "/var/lib/tomcat6-#{env}"
      )
      notifies :restart, "service[tomcat-#{env}]"
    end
  end

  init_script_path = "/etc/init.d/tomcat6-#{env}"
  template init_script_path do
    source "init.d_tomcat6.erb"
    owner "root"
    group "root"
    mode 00755
    variables(
      base_service_name: 'tomcat6',
      environment: env,
      service_name: "tomcat6-#{env}",
      init_script_path: init_script_path
    )
  end

  service "tomcat-#{env}" do
    case node["platform"]
      when "centos","redhat","fedora","amazon"
        service_name "tomcat#{node["tomcat"]["base_version"]}-#{env}"
        supports :restart => true, :status => true
      when "debian","ubuntu"
        service_name "tomcat#{node["tomcat"]["base_version"]}-#{env}"
        supports :restart => true, :reload => false, :status => true
      when "smartos"
        service_name "tomcat-#{env}"
        supports :restart => true, :reload => false, :status => true
      else
        service_name "tomcat#{node["tomcat"]["base_version"]}-#{env}"
    end
    action [:enable, :start]
    retries 4
    retry_delay 30
  end

  unless node['tomcat']["ssl_cert_file"].nil?
    script "create_#{env}_tomcat_keystore" do
      interpreter "bash"
      action :nothing
      cwd "/var/lib/tomcat6-#{env}/conf"
      code <<-EOH
        cat #{node['tomcat']['ssl_chain_files'].join(' ')} > cacerts.pem
        openssl pkcs12 -export \
         -inkey #{node['tomcat']['ssl_key_file']} \
         -in #{node['tomcat']['ssl_cert_file']} \
         -chain \
         -CAfile cacerts.pem \
         -password pass:#{node['tomcat']['keystore_password']} \
         -out #{node['tomcat']['keystore_file']}
      EOH
      notifies :restart, "service[tomcat-#{env}]"
    end
    cookbook_file "/var/lib/tomcat6-#{env}/conf/#{node['tomcat']['ssl_cert_file']}" do
      mode "0644"
      notifies :run, "script[create_tomcat_keystore]"
    end
    cookbook_file "/var/lib/tomcat6-#{env}/conf/#{node['tomcat']['ssl_key_file']}" do
      mode "0644"
      notifies :run, "script[create_tomcat_keystore]"
    end
    node['tomcat']['ssl_chain_files'].each do |cert|
      cookbook_file "/var/lib/tomcat6-#{env}/conf/#{cert}" do
        mode "0644"
        notifies :run, "script[create_tomcat_keystore]"
      end
    end
  else
    execute "Create #{env} Tomcat SSL certificate" do
      group node['tomcat']['group']
      command "#{node['tomcat']['keytool']} -genkeypair -keystore \"/var/lib/tomcat6-#{env}/conf/#{node['tomcat']['keystore_file']}\" -storepass \"#{node['tomcat']['keystore_password']}\" -keypass \"#{node['tomcat']['keystore_password']}\" -dname \"#{node['tomcat']['certificate_dn']}\""
      umask 0007
      creates "/var/lib/tomcat6-#{env}/conf/#{node['tomcat']['keystore_file']}"
      action :run
      notifies :restart, "service[tomcat-#{env}]"
    end
  end
end
#endregion

template "/usr/sbin/deploy-war" do
  source "deploy-war.sh.erb"
  owner "root"
  group "root"
  mode 00755
  variables(
    manager_user: data_bag_item("tomcat_users", "deployer")['id'],
    manager_password: data_bag_item("tomcat_users", "deployer")['password'],
    blue_http_port: node['tomcat']['blue_http_port'],
    green_http_port: node['tomcat']['green_http_port'],
  )
end

unless node['tomcat']["truststore_file"].nil?
  cookbook_file "#{node['tomcat']['config_dir']}/#{node['tomcat']['truststore_file']}" do
    mode "0644"
  end
end

include_recipe "java"

user "jstatd" do
  comment "system guy"
  system true
  shell "/bin/false"
end

group "jstatd" do
  action :create
  members "jstatd"
  append true
end

template "/etc/jstatd/jstatd.policy" do
  owner "jstatd"
  group "jstatd"
  mode 00644
end

init_script_path = "/etc/init.d/jstatd"
template init_script_path do
  source "init.d_jstatd.erb"
  owner "root"
  group "root"
  mode 00755
  variables(
    java_home: node['java']['java_home'],
    init_script_path: init_script_path
  )
  notifies :enable, "service[jstatd]"
  notifies :start, "service[jstatd]"
end

service "jstatd" do
  action :nothing
end

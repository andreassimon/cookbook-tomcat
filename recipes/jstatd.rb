include_recipe "java"

directory "/etc/jstatd" do
  owner "root"
  group "root"
  mode 00755
end

template "/etc/jstatd/jstatd.policy" do
  owner "root"
  group "root"
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
end

service "jstatd" do
  action :nothing
end

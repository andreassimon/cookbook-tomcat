include_recipe "java"

template "#{node['java']['java_home']}/jre/lib/security/jstatd.policy" do
  owner "uucp"
  group "143"
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
  notifies [:enable, :start], "service[jstatd]"
end

service "jstatd" do
  action :nothing
end

include_recipe "java"

template "#{node['java']['java_home']}/jre/lib/security/jstatd.policy" do
  owner "uucp"
  group "143"
  mode 00644
end

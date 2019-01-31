## 支持的功能


## 使用步骤:

1. 编辑 auth.conf 文件,配置用户名和密码
2. 编辑 hw_resource_manager.py, 配置授权白名单, 只有在白名单中的用户才能创建虚拟机.
  ```
        self.auth_users = {'m00401111': 'mayun'
                            }
   ```

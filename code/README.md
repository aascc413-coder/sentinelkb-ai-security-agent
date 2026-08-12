# SentinelKB 运行目录

完整介绍与学习路线请返回上一级查看 `README.md` 和 `学习资料/`。

## 启动

```powershell
Copy-Item python/.env.example python/.env
# 编辑 python/.env，填写模型服务配置
docker compose up -d --build
```

- Web 控制台：<http://localhost:8080>
- Swagger API：<http://localhost:8080/docs>
- Neo4j Browser：<http://localhost:7474>

## 测试

```powershell
cd python
python -m pytest -q
```

请勿把 `.env`、真实安全日志、客户数据或恶意样本提交到代码仓库。

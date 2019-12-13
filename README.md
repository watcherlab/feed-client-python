# 守望者实验室威胁情报Feed系统
**守望者实验室威胁情报Feed系统数据查询和下载官方python客户端**

## 说明
* 本客户端旨在提供一种易于使用的威胁情报数据查询和下载方式


## 客户端安装
```bash
pip install watcherlab-ti-client-python
```


## 客户端示例
```python
# 引入情报查询和下载客户端
from watcherlab import feed

# 创建一个查询对象，可提供Token
# 拥有Token可以查询更多的数据种类并且有较为宽泛的查询限制
# 获取Token请前往: https://feed.watcherlab.com
querier = feed.Query(token="TOKEN")

# 使用无需Token认证的匿名查询
result = querier.anonymous(data="DATA")

# 使用需要经过Token认证的高级查询
result = querier.advanced(data="DATA")

# 使用批量查询，需要Token认证
result = querier.many("DATA1","DATA2",...)

# 查询APT报告，需要Token认证
# 至少需要提供一种查询条件
# 返回的结果可能较大并且，如需下载报告的原始PDF文件请将fileUuid提交至下载PDF文件接口
result = querier.apt(...)

# 以符合国标GB/T 36643-2018的威胁情报共享数据格式查询数据，需要Token认证
result = querier.gbt(...)


# 创建一个下载对象，可提供Token
# 可以用来下载我们每日构建的威胁情报数据压缩文件以及原始APT报告的PDF文件
downloader = feed.Download(token="TOKEN")

# 下载原始APT报告的PDF文件，需要Token认证
stream = downloader.pdf(uuid="fileUuid")

# 下载每日构建的威胁情报数据压缩文件列表，需要Token认证
# 参数date设置下载数据文件的日期，1为昨天（最新的）2为前天，以此类推
result = downloader.list(date=1)

# 下载每日构建的威胁情报数据压缩文件，需要Token认证
# 参数path设置将数据文件保存到的目录路径
# 参数date设置下载数据文件的日期，1为昨天（最新的）2为前天，以此类推
# 返回所有可下载的数据文件数量以及成功下载的数据文件数量
data_count, download_count = downloader.advanced(path="PATH",date=1)

```

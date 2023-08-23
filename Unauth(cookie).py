# coding=utf-8
from burp import IBurpExtender
from burp import IProxyListener

# 所有插件都必须实现BurpExtender类，这里继承了IBurpExtender, IProxyListener类
class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        '''
        该方法在启动插件时会自动调用，用于注册插件。
        :param callbacks: callbacks是一个IBurpExtenderCallbacks，里面提供了很多基础方法，如注册监听器等。
        :return:
        '''
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks

        # 设置插件名称
        callbacks.setExtensionName("Unauth(cookie)")
        # registerProxyListener 用于获取 Proxy 模块内所有的历史请求，并返回一个 IHttpRequestResponse 类型的数组。如果想在安装插件的时候自动扫描历史请求，可以使用这个方法
        callbacks.registerProxyListener(self)


    # IProxyListener类中的方法
    def processProxyMessage(self, messageIsRequest, message):

        '''
        :param messageIsRequest: 表示此次处理的是请求还是响应
        :param message: 表示一个被拦截HTTP消息对象，可通过该对象的	getMessageInfo()方法获取到具体的请求、响应详情信息
        '''

        if messageIsRequest:
            # 获取到请求的具体详情，其值是IHttpRequestResponse对象
            messageInfo = message.getMessageInfo()

            # 获取请求的服务器地址IHttpService对象
            httpService = messageInfo.getHttpService()

            # 得到一个IRequestInfo对象
            requestInfo = self._helpers.analyzeRequest(httpService, messageInfo.getRequest())

            # 获取请求对象的URL
            url = requestInfo.getUrl().toString()

            # 获取请求对象的请求方法
            method = requestInfo.getMethod()

            # 获取请求对象的请求头，类型为数组
            headers = requestInfo.getHeaders()
            if (not self.checkSuffix(url)):
                if self.isContain("Cookie:",headers):
                    # 把请求头中Cookie字段删除，组成新的请求头数组
                    newHeaders = [header for header in headers if not header.startswith("Cookie:")]

                    # 根据删除Cookie请求头、原始body，重新组装请求
                    modifiedRequest = self._helpers.buildHttpMessage(newHeaders,
                                                                     messageInfo.getRequest()[requestInfo.getBodyOffset():])

                    # 发送修改后的请求
                    response = self.makeHttpRequest(httpService, modifiedRequest)

                    # 解析返回
                    responseInfo = self._helpers.analyzeResponse(response.getResponse())

                    # 得到返回包的body
                    responseBody = response.getResponse()[responseInfo.getBodyOffset():]

                    # Print the relevant information
                    print("===================================================================================")
                    print("modiry", url)
                    # print("Method:", method)
                    # print("Request Headers:", self._helpers.bytesToString(modifiedRequest)[:requestInfo.getBodyOffset()])

                    # Print the response body of the modified request
                    print("Modified Request Response Body:", url,self._helpers.bytesToString(responseBody))

                    # 发送原始请求
                    originalResponse = self.makeHttpRequest(httpService, messageInfo.getRequest())

                    # 解析返回
                    originalResponseInfo = self._helpers.analyzeResponse(originalResponse.getResponse())

                    # 得到返回包的body
                    originalResponseBody = originalResponse.getResponse()[originalResponseInfo.getBodyOffset():]

                    print("Original Request Response Body:", url,self._helpers.bytesToString(originalResponseBody))

                    # 对比两次返回的值是否一直
                    if self._helpers.bytesToString(responseBody) == self._helpers.bytesToString(originalResponseBody):
                        # 在proxy栏里边将该请求标记为红色
                        messageInfo.setHighlight("red")

                    print("***********************************************************************************")


    def makeHttpRequest(self, httpService, request):
        '''
        用于 发起 HTTP/1请求
        :param httpService:
        :param request:
        :return:
        '''

        return self._callbacks.makeHttpRequest(httpService, request)

    def isContain(self,findStr,lis):
        '''
        查找findStr字符串是否存在headers中
        :param findStr: 查找字符串
        :param headers: 查找的数据
        :return:
        '''
        for li in lis:
            if li.startswith(findStr):
                return True
        return False

    def checkSuffix(self,url):
        '''
        根据url判断是否访问图片等资源，当访问资源是图片、js时返回True，不是的话返回False
        :param url: url
        :return:
        '''
        suffixBlack = [
            ".js", ".jsx", ".coffee", ".ts",
            ".css", ".less", ".scss", ".sass",
            ".ico", ".jpg", ".png", ".gif", ".bmp", ".svg",
            ".ttf", ".eot", ".woff", ".woff2",
            ".ejs", ".jade", ".vue"
        ]
        for suffix in suffixBlack:
            if url.endswith(suffix):
                return True
        return False

# -*- coding: UTF-8 -*-
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JTextArea, JScrollPane, JButton, JLabel, JPanel
from java.awt import GridBagConstraints, GridBagLayout
from javax.swing import JOptionPane

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RequestDropper")

        # 创建 GUI 配置选项卡
        self.tab = JPanel()
        layout = GridBagLayout()
        self.tab.setLayout(layout)

        constraints = GridBagConstraints()

        # 添加第一个标签和文本区域
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 6
        self.tab.add(JLabel("Domains to drop (one per line):"), constraints)

        self.domain_area = JTextArea("", 4, 20)  # 创建文本区域
        constraints.gridx = 7
        constraints.gridy = 0
        constraints.gridwidth = 20
        self.tab.add(JScrollPane(self.domain_area), constraints)

        # 添加第二个标签和文本区域
        constraints.gridx = 0
        constraints.gridy = 6
        constraints.gridwidth = 6
        self.tab.add(JLabel("Paths to drop (one per line):"), constraints)

        self.path_area = JTextArea("", 4, 20)  # 创建文本区域
        constraints.gridx = 7
        constraints.gridy = 6
        constraints.gridwidth = 20
        self.tab.add(JScrollPane(self.path_area), constraints)

        # 添加按钮
        self.update_button = JButton("Update", actionPerformed=self.update_config)
        constraints.gridx = 5
        constraints.gridy = 10
        constraints.gridwidth = 2  # 占据两列
        self.tab.add(self.update_button, constraints)

        # 重置按钮
        self.reset_button = JButton("Reset", actionPerformed=self.reset_config)
        constraints.gridx = 8
        constraints.gridy = 10
        constraints.gridwidth = 2  # 占据两列
        self.tab.add(self.reset_button, constraints)

        # 将自定义选项卡添加到 Burp UI
        callbacks.addSuiteTab(self)

        # 初始化配置
        self.domains_to_drop = []
        self.paths_to_drop = []

        # 注册 HTTP 监听器
        callbacks.registerHttpListener(self)

    # 实现 ITab 接口的方法
    def getTabCaption(self):
        return "Request Dropper Config"

    def getUiComponent(self):
        return self.tab

    # 更新配置的回调方法
    def update_config(self, event):
        self.domains_to_drop = self.domain_area.getText().splitlines()
        self.paths_to_drop = self.path_area.getText().splitlines()
        message = "Domains updated:\n{}\n\nPaths updated:\n{}".format(";".join([s.encode('utf-8') for s in self.domains_to_drop]), ";".join([s.encode('utf-8') for s in self.paths_to_drop]))
        JOptionPane.showMessageDialog(None, message, "Configuration Updated", JOptionPane.INFORMATION_MESSAGE)

    def reset_config(self, event):
        self.domain_area.setText("")
        self.path_area.setText("")


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(messageInfo)
            headers = analyzedRequest.getHeaders()
            url = analyzedRequest.getUrl()
            if self.should_drop(url):
                self.drop_request(messageInfo)
                print("{} 已被删除".format( url))
                # self._callbacks.removeFromProxyHistory(messageInfo)
                return  # Drop the request

        return  # Forward the response

    def should_drop(self, url):
        for domain in self.domains_to_drop:
            if domain in url.getHost():
                print("命中 {}，{}已被拦截".format(domain,url))
                return True

        for path in self.paths_to_drop:
            if path in url.getPath():
                print("命中 {}，{}已被拦截".format(path, url))
                return True
        return False

    def drop_request(self, messageInfo):
        # Replace the request with an empty request
        messageInfo.setRequest(self._helpers.buildHttpMessage([], b""))


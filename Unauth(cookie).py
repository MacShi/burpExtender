# coding=utf-8
from burp import IBurpExtender
from burp import IProxyListener


class BurpExtender(IBurpExtender, IProxyListener):

    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks  # Store the callbacks object
        callbacks.setExtensionName("Unauth(cookie)")
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            messageInfo = message.getMessageInfo()
            httpService = messageInfo.getHttpService()
            requestInfo = self._helpers.analyzeRequest(httpService, messageInfo.getRequest())
            url = requestInfo.getUrl()
            method = requestInfo.getMethod()
            headers = requestInfo.getHeaders()

            # Remove the Cookie header from the request headers
            newHeaders = [header for header in headers if not header.startswith("Cookie:")]

            # Reconstruct the modified request
            modifiedRequest = self._helpers.buildHttpMessage(newHeaders,
                                                             messageInfo.getRequest()[requestInfo.getBodyOffset():])

            # Make the modified request using a proxy
            response = self.makeHttpRequest(httpService, modifiedRequest)

            # Process the response
            responseInfo = self._helpers.analyzeResponse(response.getResponse())
            responseBody = response.getResponse()[responseInfo.getBodyOffset():]

            # Print the relevant information
            print("===================================================================================")
            # print("modiry", url)
            # print("Method:", method)
            # print("Request Headers:", self._helpers.bytesToString(modifiedRequest)[:requestInfo.getBodyOffset()])

            # Print the response body of the modified request
            print("Modified Request Response Body:", url,self._helpers.bytesToString(responseBody))

            # Original request without modification
            originalResponse = self.makeHttpRequest(httpService, messageInfo.getRequest())
            originalResponseInfo = self._helpers.analyzeResponse(originalResponse.getResponse())
            originalResponseBody = originalResponse.getResponse()[originalResponseInfo.getBodyOffset():]

            # Print the response body of the original request
            print("Original Request Response Body:", url,self._helpers.bytesToString(originalResponseBody))
            if self._helpers.bytesToString(responseBody) == self._helpers.bytesToString(originalResponseBody):
                messageInfo.setHighlight("red")

            print("***********************************************************************************")

    def makeHttpRequest(self, httpService, request):
        # Make the request using the proxy
        return self._callbacks.makeHttpRequest(httpService, request)

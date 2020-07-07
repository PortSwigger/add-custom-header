package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.Arrays;
import javax.swing.JPanel;

import javax.swing.SwingUtilities;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab {

    IExtensionHelpers helpers = null;
    Pattern p;

    static String extensionName = "Add Custom Header";
    IBurpExtenderCallbacks callbacks = null;

    // some default values
    final String DEFAULT_HEADER_NAME = "Authorization";
    final String DEFAULT_HEADER_VALUE_PREFIX = "Bearer ";
    final String DEFAULT_REGEXP = "access_token\":\"(.*?)\"";
    final String DEFAULT_HARDCODED_VALUE = "<insert static JWT token here>";

    private BurpTab tab;

    void useRegExp() {

    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(extensionName);
        this.helpers = callbacks.getHelpers();
        callbacks.registerSessionHandlingAction(this);

        // create our UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                tab = new BurpTab();

                // set some default values
                tab.setHeaderName(DEFAULT_HEADER_NAME);
                tab.setHeaderValuePrefix(DEFAULT_HEADER_VALUE_PREFIX);
                tab.setRegExpText(DEFAULT_REGEXP);
                tab.setHardCodedText(DEFAULT_HARDCODED_VALUE);
                // force update the example label
                tab.updateFinalResultLabel();
                // customize our UI components
                callbacks.customizeUiComponent(tab);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

        callbacks.printOutput("Add Header Extension loaded");
    }

    // methods below from ISessionHandlingAction
    @Override
    public String getActionName() {
        return extensionName;
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest,
            IHttpRequestResponse[] macroItems) {

        String token = null;

        if (tab.useHardCoded()) {
            // token has priority over regexp
            token = tab.getHardCodedText();
        } else if (tab.useRegExp()) {
            if (macroItems.length == 0) {
                this.callbacks.issueAlert("No macro configured or macro did not return any response");
                return;
            }
            String regexp = tab.getRegExpText();
            try {
                p = Pattern.compile(regexp);
            } catch (PatternSyntaxException e) {
                this.callbacks.issueAlert("Syntax error in regular expression (see extension error window)");
                callbacks.printError(e.toString());
                return;
            }

            // go through all macros and run the regular expression on their body
            for (int i = 0; i < macroItems.length; i++) {
                byte[] _responseBody = macroItems[i].getResponse();
                if (_responseBody == null) return;
                IResponseInfo macroResponse = helpers.analyzeResponse(_responseBody);
                if (macroResponse == null ) return;
                String responseBody = helpers.bytesToString(_responseBody);
                Matcher m = p.matcher(responseBody);
                if (m.find()) {
                    token = m.group(1);
                    if (token != null && token.length() > 0) {
                        // found it
                        break;
                    }
                }
            }
        } else {
            // using the 'disable' button
            return;
        }

        if (token == null) {
            // nothing found: failing silently to avoid polluting the logs
            callbacks.printError("No token found");
            return;
        }

        String headerName = tab.getHeaderName();
        String headerValuePrefix = tab.getHeaderValuePrefix();
        
        IRequestInfo rqInfo = helpers.analyzeRequest(currentRequest);
        // retrieve all headers
        ArrayList<String> headers = (ArrayList<String>) rqInfo.getHeaders();
        for (int i = 0; i < headers.size(); i++) {
            if (((String) headers.get(i)).startsWith(headerName + ": " + headerValuePrefix)) {
                // there could be more than one header like this; remove and continue
                headers.remove(i);
            }
        }
        String newHeader = headerName + ": " + headerValuePrefix + token;
        headers.add(newHeader);
        callbacks.printOutput("Added header: '" + newHeader + "'");

        byte[] message = helpers.buildHttpMessage(headers, Arrays.copyOfRange(currentRequest.getRequest(), rqInfo.getBodyOffset(), currentRequest.getRequest().length));
        currentRequest.setRequest(message);
    }
    // end ISessionHandlingAction methods

    // ITab methods
    @Override
    public String getTabCaption() {
        return extensionName;
    }

    @Override
    public Component getUiComponent() {
        return tab;
    }
    // end ITab methods

}

function sendTtps(tactic_id, tactic_name, technique_id, technique_name, operator, context, confidence) {
    send({
        type: 'ttp',
        data: {
            tactic_id: tactic_id,
            tactic_name: tactic_name,
            technique_id: technique_id,
            technique_name: technique_name,
            operator: operator,
            context: context,
            confidence: confidence,
            execution_timestamp: Date.now()
        }
    });
}

const CONFIDENCE = {
    LOW: 'LOW',
    MEDIUM: 'MEDIUM',
    HIGH: 'HIGH'
}

// Java ================================================
Java.perform(function () {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const SystemLoad_2 = System.loadLibrary.overload('java.lang.String');
    const VMStack = Java.use('dalvik.system.VMStack');

    // System.loadLibrary
    SystemLoad_2.implementation = function (library) {
        try {
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);

            if (!library.includes("monochrome") && !library.includes("webviewchromium_plat_support")) {
                sendTtps('TA0041', 'Execution', 'T1575', 'Native API', 'System.loadLibrary', 'library=' + library, CONFIDENCE.HIGH);
                sendTtps('TA0030', 'Defense Evasion', 'T1575', 'Native API', 'System.loadLibrary', 'library=' + library, CONFIDENCE.HIGH);
            }

            return loaded;
        } catch (ex) {
            console.log(ex);
        }
    };

    // Service
    const Service = Java.use('android.app.Service');
    Service.startForeground.overload('int', 'android.app.Notification').implementation = function (arg1, arg2) {
        sendTtps('TA0028', 'Persistence', 'T1541', 'Foreground Persistence', 'Service.startForeground', 'arg1=' + arg1 + ', arg2=' + arg2, CONFIDENCE.HIGH);
        return this.startForeground(arg1, arg2);
    };
    Service.startForeground.overload('int', 'android.app.Notification', 'int').implementation = function (arg1, arg2, arg3) {
        sendTtps('TA0028', 'Persistence', 'T1541', 'Foreground Persistence', 'Service.startForeground', 'arg1=' + arg1 + ', arg2=' + arg2 + ', arg3=' + arg3, CONFIDENCE.HIGH);
        return this.startForeground(arg1, arg2, arg3);
    };

    // Intent
    const Intent = Java.use('android.content.Intent');
    const ADD_DEVICE_ADMIN = 'android.app.action.ADD_DEVICE_ADMIN';
    const UNINSTALL_PACKAGE = 'android.intent.action.UNINSTALL_PACKAGE';
    const MANAGE_UNKNOWN_APP_SOURCES = 'android.settings.MANAGE_UNKNOWN_APP_SOURCES';
    const ACTION_CALL = 'android.intent.action.CALL';
    const ACTION_DIAL = 'android.intent.action.DIAL';
    const ACTION_MANAGE_OVERLAY_PERMISSION = 'android.settings.ACTION_MANAGE_OVERLAY_PERMISSION';
    const ACTION_ADD_DEVICE_ADMIN = 'android.app.action.ADD_DEVICE_ADMIN';
    Intent.$init.overload('java.lang.String').implementation = function (action) {
        if (action.includes(ADD_DEVICE_ADMIN)) {
            sendTtps('TA0029', 'Privilege Escalation', 'T1626.001', 'Abuse Elevation Control Mechanism: Device Administrator Permissions', 'Intent.<init>', 'action=' + action, CONFIDENCE.HIGH);
        }

        if (action.includes(UNINSTALL_PACKAGE)) {
            sendTtps('TA0030', 'Defense Evasion', 'T1630.001', 'Indicator Removal on Host: Uninstall Malicious Application', 'Intent.<init>', 'action=' + action, CONFIDENCE.HIGH);
        }

        if (action.includes(MANAGE_UNKNOWN_APP_SOURCES)) {
            sendTtps('TA0030', 'Defense Evasion', 'T1632.001', 'Subvert Trust Controls: Code Signing Policy Modification', 'Intent.<init>', 'action=' + action, CONFIDENCE.HIGH);
        }

        if (action.includes(ACTION_CALL) || action.includes(ACTION_DIAL)) {
            sendTtps('TA0035', 'Collection', 'T1616', 'Call Control', 'Intent.<init>', 'action=' + action, CONFIDENCE.HIGH);
        }

        if (action.includes(ACTION_MANAGE_OVERLAY_PERMISSION)) {
            sendTtps('TA0030', 'Defense Evasion', 'T1628.002', 'User Evasion', 'Intent.<init>', 'action=' + action, CONFIDENCE.HIGH);
            sendTtps('TA0031', 'Credential Access', 'T1417.002', 'GUI Input Capture', 'Intent.<init>', 'action=' + action, CONFIDENCE.HIGH);
        }

        if (action.includes(ACTION_ADD_DEVICE_ADMIN)) {
            sendTtps('TA0029', 'Privilege Escalation', 'T1626.001', 'Privilege Escalation: Device Administrator Permissions', 'Intent.<init>', 'action=' + action, CONFIDENCE.HIGH);
        }

        this.$init(action);
    }

    // DexClassLoader
    const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        sendTtps('TA0030', 'Defense Evasion', 'T1670', 'Virtualization Solution', 'DexClassLoader.<init>', 'dexPath=' + dexPath + ', optimizedDirectory=' + optimizedDirectory + ', librarySearchPath=' + librarySearchPath, CONFIDENCE.HIGH);
        this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    }

    // WebView
    const WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        sendTtps('TA0030', 'Defense Evasion', 'T1407', 'Download New Code at Runtime', 'WebView.loadUrl', 'url=' + url, CONFIDENCE.HIGH);
        return this.loadUrl(url);
    }
    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, additionalHttpHeaders) {
        sendTtps('TA0030', 'Defense Evasion', 'T1407', 'Download New Code at Runtime', 'WebView.loadUrl', 'url=' + url + ', headers=' + additionalHttpHeaders, CONFIDENCE.HIGH);
        return this.loadUrl(url, additionalHttpHeaders);
    }

    // PackageManager
    const PackageManager = Java.use("android.content.pm.PackageManager");
    const COMPONENT_ENABLED_STATE_DISABLED = 0x2;
    const DONT_KILL_APP = 0x1;
    PackageManager.setComponentEnabledSetting.overload('android.content.ComponentName', 'int', 'int').implementation = function (componentName, newState, flags) {
        if ((newState & COMPONENT_ENABLED_STATE_DISABLED) !== 0 && (flags & DONT_KILL_APP) !== 0) {
            sendTtps('TA0030', 'Defense Evasion', 'T1628.001', 'Hide Artifacts: Suppress Application Icon', 'PackageManager.setComponentEnabledSetting', 'component=' + componentName.getClassName() + ', newState=' + newState + ', flags=' + flags, CONFIDENCE.HIGH);
        }
        return this.setComponentEnabledSetting(componentName, newState, flags);
    }
    PackageManager.setApplicationEnabledSetting.overload('java.lang.String', 'int', 'int').implementation = function (packageName, newState, flags) {
        if ((newState & COMPONENT_ENABLED_STATE_DISABLED) !== 0 && (flags & DONT_KILL_APP) !== 0) {
            sendTtps('TA0030', 'Defense Evasion', 'T1628.001', 'Hide Artifacts: Suppress Application Icon', 'PackageManager.setApplicationEnabledSetting', 'package=' + packageName + ', newState=' + newState + ', flags=' + flags, CONFIDENCE.HIGH);
        }
        return this.setApplicationEnabledSetting(packageName, newState, flags);
    }
    PackageManager.getInstalledApplications.overload('int').implementation = function (flags) {
        sendTtps('TA0032', 'Discovery', 'T1418', 'Software Discovery', 'PackageManager.getInstalledApplications', 'flags=' + flags, CONFIDENCE.MEDIUM);
        sendTtps('TA0032', 'Discovery', 'T1418.001', 'Software Discovery: Security Software Discovery', 'PackageManager.getInstalledApplications', 'flags=' + flags, CONFIDENCE.MEDIUM);
        return this.getInstalledApplications(flags);
    }

    // SensorManager
    const SensorManager = Java.use("android.hardware.SensorManager");
    const TYPE_ACCELEROMETER = 0x1;
    const TYPE_GYROSCOPE = 0x4;
    SensorManager.getDefaultSensor.overload('int').implementation = function (type) {
        if (type == TYPE_ACCELEROMETER || type == TYPE_GYROSCOPE) {
            sendTtps('TA0030', 'Defense Evasion', 'T1628.002', 'Hide Artifacts: User Evasion', 'SensorManager.getDefaultSensor', 'type=' + type, CONFIDENCE.MEDIUM);
        }
        return this.getDefaultSensor(type);
    }
    SensorManager.getDefaultSensor.overload('int', 'boolean').implementation = function (type, wakeUp) {
        if (type == TYPE_ACCELEROMETER || type == TYPE_GYROSCOPE) {
            sendTtps('TA0030', 'Defense Evasion', 'T1628.002', 'Hide Artifacts: User Evasion', 'SensorManager.getDefaultSensor', 'type=' + type + ', wakeUp=' + wakeUp, CONFIDENCE.MEDIUM);
        }
        return this.getDefaultSensor(type, wakeUp);
    }
    SensorManager.registerListener.overload('android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int').implementation = function (listener, sensor, rate) {
        sendTtps('TA0030', 'Defense Evasion', 'T1628.002', 'Hide Artifacts: User Evasion', 'SensorManager.registerListener', 'sensor=' + sensor.getName() + ', rate=' + rate, CONFIDENCE.MEDIUM);
        return this.registerListener(listener, sensor, rate);
    }

    // AccessibilityService
    const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
    const GLOBAL_ACTION_BACK = 0x1
    const GLOBAL_ACTION_HOME = 0x2
    AccessibilityService.performGlobalAction.overload('int').implementation = function (action) {
        if (action === GLOBAL_ACTION_BACK || action === GLOBAL_ACTION_HOME) {
            sendTtps('TA0030', 'Defense Evasion', 'T1629.001', 'Impair Defenses: Prevent Application Removal', 'AccessibilityService.performGlobalAction', 'action=' + action, CONFIDENCE.MEDIUM);
        }
        sendTtps('TA0030', 'Defense Evasion', 'T1516', 'Input Injection', 'AccessibilityService.performGlobalAction', 'action=' + action, CONFIDENCE.HIGH);
        sendTtps('TA0031', 'Credential Access', 'T1453', 'Abuse Accessibility Features', 'AccessibilityService.performGlobalAction', 'action=' + action, CONFIDENCE.HIGH);
        return this.performGlobalAction(action);
    }
    AccessibilityService.dispatchGesture.overload('android.accessibilityservice.GestureDescription', 'android.accessibilityservice.AccessibilityService$GestureResultCallback', 'android.os.Handler').implementation = function (gestureDescription, callback, handler) {
        sendTtps('TA0030', 'Defense Evasion', 'T1516', 'Input Injection', 'AccessibilityService.dispatchGesture', 'gestureDescription=' + gestureDescription + ', callback=' + callback, CONFIDENCE.HIGH);
        sendTtps('TA0031', 'Credential Access', 'T1453', 'Abuse Accessibility Features', 'AccessibilityService.dispatchGesture', 'gestureDescription=' + gestureDescription + ', callback=' + callback, CONFIDENCE.HIGH);
        return this.dispatchGesture(gestureDescription, callback, handler);
    }

    // AccessibilityNodeInfo
    const AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    AccessibilityNodeInfo.performAction.overload('int').implementation = function (action) {
        sendTtps('TA0031', 'Credential Access', 'T1453', 'Abuse Accessibility Features', 'AccessibilityNodeInfo.performAction', 'action=' + action, CONFIDENCE.HIGH);
        return this.performAction(action);
    }
    AccessibilityNodeInfo.performAction.overload('int', 'android.os.Bundle').implementation = function (action, args) {
        sendTtps('TA0031', 'Credential Access', 'T1453', 'Abuse Accessibility Features', 'AccessibilityNodeInfo.performAction', 'action=' + action + ', args=' + args, CONFIDENCE.HIGH);
        return this.performAction(action, args);
    }
    AccessibilityNodeInfo.getText.overload().implementation = function () {
        sendTtps('TA0031', 'Credential Access', 'T1453', 'Abuse Accessibility Features', 'AccessibilityNodeInfo.getText', '', CONFIDENCE.HIGH);
        return this.getText();
    }
    AccessibilityNodeInfo.findAccessibilityNodeInfosByText.overload('java.lang.String').implementation = function (text) {
        sendTtps('TA0031', 'Credential Access', 'T1453', 'Abuse Accessibility Features', 'AccessibilityNodeInfo.findAccessibilityNodeInfosByText', 'text=' + text, CONFIDENCE.HIGH);
        return this.findAccessibilityNodeInfosByText(text);
    }

    // DevicePolicyManager
    const DevicePolicyManager = Java.use("android.app.admin.DevicePolicyManager");
    DevicePolicyManager.lockNow.overload().implementation = function () {
        sendTtps('TA0030', 'Defense Evasion', 'T1629.002', 'Impair Defenses: Device Lockout', 'DevicePolicyManager.lockNow', '', CONFIDENCE.HIGH);
        sendTtps('TA0034', 'Impact', 'T1642', 'Endpoint Denial of Service', 'DevicePolicyManager.lockNow', '', CONFIDENCE.HIGH);
        return this.lockNow();
    }
    DevicePolicyManager.lockNow.overload('int').implementation = function (flags) {
        sendTtps('TA0030', 'Defense Evasion', 'T1629.002', 'Impair Defenses: Device Lockout', 'DevicePolicyManager.lockNow', 'flags=' + flags, CONFIDENCE.HIGH);
        sendTtps('TA0034', 'Impact', 'T1642', 'Endpoint Denial of Service', 'DevicePolicyManager.lockNow', 'flags=' + flags, CONFIDENCE.HIGH);
        return this.lockNow(flags);
    }
    DevicePolicyManager.wipeData.overload('int').implementation = function (flags) {
        sendTtps('TA0030', 'Defense Evasion', 'T1630.002', 'Indicator Removal on Host: File Deletion', 'DevicePolicyManager.wipeData', 'flags=' + flags, CONFIDENCE.HIGH);
        sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'DevicePolicyManager.wipeData', 'flags=' + flags, CONFIDENCE.HIGH);
        return this.wipeData(flags);
    }
    DevicePolicyManager.wipeData.overload('int', 'java.lang.CharSequence').implementation = function (flags, reason) {
        sendTtps('TA0030', 'Defense Evasion', 'T1630.002', 'Indicator Removal on Host: File Deletion', 'DevicePolicyManager.wipeData', 'flags=' + flags + ', reason=' + reason, CONFIDENCE.HIGH);
        sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'DevicePolicyManager.wipeData', 'flags=' + flags + ', reason=' + reason, CONFIDENCE.HIGH);
        return this.wipeData(flags, reason);
    }
    DevicePolicyManager.resetPassword.overload('java.lang.String', 'int').implementation = function (password, flags) {
        sendTtps('TA0034', 'Impact', 'T1640', 'Account Access Removal', 'DevicePolicyManager.resetPassword', 'password=' + password + ', flags=' + flags, CONFIDENCE.HIGH);
        sendTtps('TA0034', 'Impact', 'T1642', 'Endpoint Denial of Service', 'DevicePolicyManager.resetPassword', 'password=' + password + ', flags=' + flags, CONFIDENCE.HIGH);
        return this.resetPassword(password, flags);
    }

    // NotificationListenerService
    const NotificationListenerService = Java.use("android.service.notification.NotificationListenerService");
    NotificationListenerService.onNotificationPosted.overload('android.service.notification.StatusBarNotification', 'android.service.notification.NotificationListenerService$RankingMap').implementation = function (sbn, rankingMap) {
        sendTtps('TA0031', 'Credential Access', 'T1517', 'Access Notifications', 'NotificationListenerService.onNotificationPosted', 'sbn=' + sbn, CONFIDENCE.HIGH);
        return this.onNotificationPosted(sbn, rankingMap);
    }
    NotificationListenerService.onNotificationRemoved.overload('android.service.notification.StatusBarNotification', 'android.service.notification.NotificationListenerService$RankingMap').implementation = function (sbn, rankingMap) {
        sendTtps('TA0031', 'Credential Access', 'T1517', 'Access Notifications', 'NotificationListenerService.onNotificationRemoved', 'sbn=' + sbn, CONFIDENCE.HIGH);
        return this.onNotificationRemoved(sbn, rankingMap);
    }
    NotificationListenerService.cancelNotification.overload('java.lang.String').implementation = function (key) {
        sendTtps('TA0031', 'Credential Access', 'T1517', 'Access Notifications', 'NotificationListenerService.cancelNotification', 'key=' + key, CONFIDENCE.HIGH);
        return this.cancelNotification(key);
    }
    NotificationListenerService.getActiveNotifications.overload().implementation = function () {
        sendTtps('TA0031', 'Credential Access', 'T1517', 'Access Notifications', 'NotificationListenerService.getActiveNotifications', '', CONFIDENCE.HIGH);
        return this.getActiveNotifications();
    }

    // ClipboardManager
    const ClipboardManager = Java.use("android.content.ClipboardManager");
    ClipboardManager.addPrimaryClipChangedListener.overload('android.content.ClipboardManager$OnPrimaryClipChangedListener').implementation = function (listener) {
        sendTtps('TA0031', 'Credential Access', 'T1414', 'Clipboard Data', 'ClipboardManager.addPrimaryClipChangedListener', 'listener=' + listener, CONFIDENCE.HIGH);
        sendTtps('TA0034', 'Impact', 'T1641.001', 'Data Manipulation: Transmitted Data Manipulation', 'ClipboardManager.addPrimaryClipChangedListener', 'listener=' + listener, CONFIDENCE.LOW);
        return this.addPrimaryClipChangedListener(listener);
    }

    // WindowManager
    const WindowManager_LayoutParams = Java.use("android.view.WindowManager$LayoutParams");
    const TYPE_APPLICATION_OVERLAY = 0x000007f6;
    WindowManager_LayoutParams.$init.overload('int', 'int', 'int', 'int', 'int').implementation = function (width, height, type, flags, format) {
        if (type === TYPE_APPLICATION_OVERLAY) {
            sendTtps('TA0031', 'Credential Access', 'T1417.002', 'Input Capture: GUI Input Capture', 'WindowManager.LayoutParams.<init>', 'type=' + type + ', width=' + width + ', height=' + height + ', flags=' + flags, CONFIDENCE.HIGH);
        }
        return this.$init(width, height, type, flags, format);
    }

    // Environment
    const Environment = Java.use("android.os.Environment");
    Environment.getExternalStorageDirectory.implementation = function () {
        sendTtps('TA0035', 'Collection', 'T1533', 'Data from Local System', 'Environment.getExternalStorageDirectory', '', CONFIDENCE.MEDIUM);
        return this.getExternalStorageDirectory();
    }

    // Context 
    const Context = Java.use("android.content.Context");
    Context.getExternalFilesDir.overload('java.lang.String').implementation = function (type) {
        sendTtps('TA0032', 'Discovery', 'T1420', 'File and Directory Discovery', 'Context.getExternalFilesDir', 'type=' + type, CONFIDENCE.MEDIUM);
        return this.getExternalFilesDir(type);
    }

    // SystemProperties
    const SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
        if (key === 'ro.kernel.qemu' ||
            key === 'ro.product.model' ||
            key === 'ro.product.manufacturer' ||
            key === 'ro.build.fingerprint' ||
            key === 'ro.build.flavor' ||
            key === 'ro.serialno'
        ) {
            sendTtps('TA0030', 'Defense Evasion', 'T1633.001', 'Virtualization/Sandbox Evasion: System Checks', 'SystemProperties.get', 'key=' + key, CONFIDENCE.LOW);
            sendTtps('TA0032', 'Discovery', 'T1426', 'System Information Discovery', 'SystemProperties.get', 'key=' + key, CONFIDENCE.MEDIUM);
        }
        if (key === "ro.build.fingerprint" ||
            key === "ro.build.version.release" ||
            key === "ro.build.version.sdk" ||
            key === "ro.build.id" ||
            key === "ro.build.display.id" ||
            key === "ro.build.product" ||
            key === "ro.build.manufacturer" ||
            key === "ro.build.brand" ||
            key === "ro.build.model" ||
            key === "ro.build.device" ||
            key === "ro.build.tags" ||
            key === "ro.build.type" ||
            key === "ro.product.name" ||
            key === "ro.product.device" ||
            key === "ro.product.board" ||
            key === "ro.product.cpu.abi" ||
            key === "ro.product.cpu.abilist" ||
            key === "ro.product.manufacturer" ||
            key === "ro.product.model" ||
            key === "ro.serialno" ||
            key === "ro.boot.serialno" ||
            key === "ro.boot.hardware" ||
            key === "ro.hardware" ||
            key === "ro.board.platform" ||
            key === "ro.kernel.qemu" ||
            key === "ro.boot.vbmeta.device_state" ||
            key === "ro.boot.verifiedbootstate" ||
            key === "ro.boot.flash.locked" ||
            key === "ro.debuggable" ||
            key === "ro.secure") {
            sendTtps('TA0032', 'Discovery', 'T1426', 'System Information Discovery', 'SystemProperties.get', 'key=' + key, CONFIDENCE.MEDIUM);
        }
        return this.get(key);
    }

    // TelephonyManager 
    const TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getNetworkOperatorName.overload().implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getNetworkOperatorName', '', CONFIDENCE.MEDIUM);
        return this.getNetworkOperatorName();
    }
    TelephonyManager.getNetworkOperatorName.overload('int').implementation = function (slotIndex) {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getNetworkOperatorName', 'slotIndex=' + slotIndex, CONFIDENCE.MEDIUM);
        return this.getNetworkOperatorName(slotIndex);
    }
    TelephonyManager.getSimOperatorName.overload().implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getSimOperatorName', '', CONFIDENCE.MEDIUM);
        return this.getSimOperatorName();
    }
    TelephonyManager.getSimOperatorName.overload('int').implementation = function (slotIndex) {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getSimOperatorName', 'slotIndex=' + slotIndex, CONFIDENCE.MEDIUM);
        return this.getSimOperatorName(slotIndex);
    }
    TelephonyManager.getSimSerialNumber.overload().implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getSimSerialNumber', '', CONFIDENCE.MEDIUM);
        return this.getSimSerialNumber();
    }
    TelephonyManager.getSimState.overload().implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getSimState', '', CONFIDENCE.MEDIUM);
        return this.getSimState();
    }
    TelephonyManager.getSimState.overload('int').implementation = function (slotIndex) {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getSimState', 'slotIndex=' + slotIndex, CONFIDENCE.MEDIUM);
        return this.getSimState(slotIndex);
    }

    TelephonyManager.getSubscriberId.overload('int').implementation = function (slotIndex) {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getSubscriberId', 'slotIndex=' + slotIndex, CONFIDENCE.MEDIUM);
        return this.getSubscriberId(slotIndex);
    }
    TelephonyManager.getLine1Number.overload().implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getLine1Number', '', CONFIDENCE.MEDIUM);
        return this.getLine1Number();
    }
    TelephonyManager.getLine1Number.overload('int').implementation = function (slotIndex) {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getLine1Number', 'slotIndex=' + slotIndex, CONFIDENCE.MEDIUM);
        return this.getLine1Number(slotIndex);
    }
    TelephonyManager.getImei.overload().implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getImei', '', CONFIDENCE.MEDIUM);
        return this.getImei();
    }
    TelephonyManager.getImei.overload('int').implementation = function (slotIndex) {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'TelephonyManager.getImei', 'slotIndex=' + slotIndex, CONFIDENCE.MEDIUM);
        return this.getImei(slotIndex);
    }
    TelephonyManager.getAllCellInfo.overload().implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1421', 'System Network Connections Discovery', 'TelephonyManager.getAllCellInfo', '', CONFIDENCE.MEDIUM);
        return this.getAllCellInfo();
    }
    TelephonyManager.getCellLocation.overload().implementation = function () {
        sendTtps('TA0030', 'Defense Evasion', 'T1627.001', 'Execution Guardrails: Geofencing', 'TelephonyManager.getCellLocation', '', CONFIDENCE.MEDIUM);
        sendTtps('TA0032', 'Discovery', 'T1430', 'Location Tracking', 'TelephonyManager.getCellLocation', '', CONFIDENCE.MEDIUM);
        return this.getCellLocation();
    }

    // NetworkInterface
    const NetworkInterface = Java.use('java.net.NetworkInterface');
    NetworkInterface.getNetworkInterfaces.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'NetworkInterface.getNetworkInterfaces', '', CONFIDENCE.MEDIUM);
        return this.getNetworkInterfaces();
    }

    // InetAddress
    const InetAddress = Java.use('java.net.InetAddress');
    InetAddress.getHostAddress.overload().implementation = function (host) {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'InetAddress.getHostAddress', 'host=' + host, CONFIDENCE.MEDIUM);
        return this.getAllByName(host);
    }

    // NetworkInfo
    const NetworkInfo = Java.use('android.net.NetworkInfo');
    NetworkInfo.isConnected.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.001', 'System Network Configuration Discovery: Internet Connection Discovery', 'NetworkInfo.isConnected', '', CONFIDENCE.MEDIUM);
        return this.isConnected();
    }

    // WifiInfo
    const WifiInfo = Java.use('android.net.wifi.WifiInfo');
    WifiInfo.getIpAddress.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.002', 'System Network Configuration Discovery: Wi-Fi Discovery', 'WifiInfo.getIpAddress', '', CONFIDENCE.MEDIUM);
        return this.getIpAddress();
    }
    WifiInfo.getSSID.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.002', 'System Network Configuration Discovery: Wi-Fi Discovery', 'WifiInfo.getSSID', '', CONFIDENCE.MEDIUM);
        return this.getSSID();
    }
    WifiInfo.getBSSID.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.002', 'System Network Configuration Discovery: Wi-Fi Discovery', 'WifiInfo.getBSSID', '', CONFIDENCE.MEDIUM);
        return this.getBSSID();
    }

    // WifiManager
    const WifiManager = Java.use('android.net.wifi.WifiManager');
    WifiManager.isWifiEnabled.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1422.002', 'System Network Configuration Discovery: Wi-Fi Discovery', 'WifiManager.isWifiEnabled', '', CONFIDENCE.MEDIUM);
        return this.isWifiEnabled();
    }
    WifiManager.getScanResults.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1421', 'System Network Connections Discovery', 'WifiManager.getScanResults', '', CONFIDENCE.MEDIUM);
        return this.getScanResults();
    }

    // BluetoothAdapter
    const BluetoothAdapter = Java.use('android.bluetooth.BluetoothAdapter');
    BluetoothAdapter.getBondedDevices.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1421', 'System Network Connections Discovery', 'BluetoothAdapter.getBondedDevices', '', CONFIDENCE.MEDIUM);
        return this.getBondedDevices();
    }

    // LocationManager
    const LocationManager = Java.use('android.location.LocationManager');
    LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider) {
        sendTtps('TA0030', 'Defense Evasion', 'T1627.001', 'Execution Guardrails: Geofencing', 'LocationManager.getLastKnownLocation', 'provider=' + provider, CONFIDENCE.MEDIUM);
        sendTtps('TA0032', 'Discovery', 'T1430', 'Location Tracking', 'LocationManager.getLastKnownLocation', 'provider=' + provider, CONFIDENCE.MEDIUM);
        return this.getLastKnownLocation(provider);
    }

    // Location
    const Location = Java.use('android.location.Location');
    Location.getLatitude.implementation = function () {
        sendTtps('TA0030', 'Defense Evasion', 'T1627.001', 'Execution Guardrails: Geofencing', 'Location.getLatitude', '', CONFIDENCE.MEDIUM);
        sendTtps('TA0032', 'Discovery', 'T1430', 'Location Tracking', 'Location.getLatitude', '', CONFIDENCE.MEDIUM);
        return this.getLatitude();
    }
    Location.getLongitude.implementation = function () {
        sendTtps('TA0030', 'Defense Evasion', 'T1627.001', 'Execution Guardrails: Geofencing', 'Location.getLongitude', '', CONFIDENCE.MEDIUM);
        sendTtps('TA0032', 'Discovery', 'T1430', 'Location Tracking', 'Location.getLongitude', '', CONFIDENCE.MEDIUM);
        return this.getLongitude();
    }

    // ActivityManager
    const ActivityManager = Java.use('android.app.ActivityManager');
    ActivityManager.getRunningAppProcesses.implementation = function () {
        sendTtps('TA0032', 'Discovery', 'T1424', 'Process Discovery', 'ActivityManager.getRunningAppProcesses', '', CONFIDENCE.MEDIUM);
        return this.getRunningAppProcesses();
    }
    ActivityManager.getRunningTasks.overload('int').implementation = function (maxNum) {
        sendTtps('TA0032', 'Discovery', 'T1424', 'Process Discovery', 'ActivityManager.getRunningTasks', 'maxNum=' + maxNum, CONFIDENCE.MEDIUM);
        return this.getRunningTasks(maxNum);
    }

    // ZipOutputStream
    const ZipOutputStream = Java.use('java.util.zip.ZipOutputStream');
    ZipOutputStream.$init.overload('java.io.OutputStream').implementation = function (out) {
        sendTtps('TA0035', 'Collection', 'T1532', 'Archive Collected Data', 'ZipOutputStream.<init>', 'out=' + out, CONFIDENCE.LOW);
        return this.$init(out);
    }

    // Cipher
    const Cipher = Java.use('javax.crypto.Cipher');
    function hookCipherGetInstance(transformation) {
        sendTtps('TA0035', 'Collection', 'T1532', 'Archive Collected Data', 'Cipher.getInstance', 'transformation=' + transformation, CONFIDENCE.LOW);
        if (transformation.includes("AES") || transformation.includes("Blowfish") || transformation.includes("RC4")) {
            sendTtps('TA0037', 'Command and Control', 'T1521.001', 'Encrypted Channel: Symmetric Cryptography', 'Cipher.getInstance', 'transformation=' + transformation, CONFIDENCE.MEDIUM);
        }
        if (transformation.includes("RSA")) {
            sendTtps('TA0037', 'Command and Control', 'T1521.002', 'Encrypted Channel: Asymmetric Cryptography', 'Cipher.getInstance', 'transformation=' + transformation, CONFIDENCE.MEDIUM);
        }
        sendTtps('TA0034', 'Impact', 'T1471', 'Data Encrypted for Impact', 'Cipher.getInstance', 'transformation=' + transformation, CONFIDENCE.LOW);
    }
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        hookCipherGetInstance(transformation);
        return this.getInstance(transformation);
    }
    Cipher.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (transformation, provider) {
        hookCipherGetInstance(transformation);
        return this.getInstance(transformation, provider);
    }

    // MediaRecorder
    const MediaRecorder = Java.use('android.media.MediaRecorder');
    MediaRecorder.start.implementation = function () {
        sendTtps('TA0035', 'Collection', 'T1429', 'Audio Capture', 'MediaRecorder.start', '', CONFIDENCE.HIGH);
        return this.start();
    }
    MediaRecorder.setVideoSource.overload('int').implementation = function (videoSource) {
        sendTtps('TA0035', 'Collection', 'T1512', 'Video Capture', 'MediaRecorder.setVideoSource', 'videoSource=' + videoSource, CONFIDENCE.HIGH);
        return this.setVideoSource(videoSource);
    }

    // TelecomManager
    const TelecomManager = Java.use('android.telecom.TelecomManager');
    TelecomManager.acceptRingingCall.overload().implementation = function () {
        sendTtps('TA0035', 'Collection', 'T1616', 'Call Control', 'TelecomManager.acceptRingingCall', '', CONFIDENCE.HIGH);
        return this.acceptRingingCall();
    }
    TelecomManager.acceptRingingCall.overload('int').implementation = function (videoState) {
        sendTtps('TA0035', 'Collection', 'T1616', 'Call Control', 'TelecomManager.acceptRingingCall', 'videoState=' + videoState, CONFIDENCE.HIGH);
        return this.acceptRingingCall(videoState);
    }

    // SQLiteDatabase
    const SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.openDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int').implementation = function (path, factory, flags) {
        sendTtps('TA0035', 'Collection', 'T1533', 'Data from Local System', 'SQLiteDatabase.openDatabase', 'path=' + path + ', flags=' + flags, CONFIDENCE.MEDIUM);
        return this.openDatabase(path, factory, flags);
    }

    // ContentResolver
    const ContentResolver = Java.use('android.content.ContentResolver');
    function hookContentResolverQuery(uri) {
        if (uri.toString().includes("com.android.calendar")) {
            sendTtps('TA0035', 'Collection', 'T1636.001', 'Protected User Data: Calendar Entries', 'ContentResolver.query', 'uri=' + uri.toString(), CONFIDENCE.HIGH);
        } else if (uri.toString().includes("call_log")) {
            sendTtps('TA0035', 'Collection', 'T1636.002', 'Protected User Data: Call Log', 'ContentResolver.query', 'uri=' + uri.toString(), CONFIDENCE.HIGH);
        } else if (uri.toString().includes("contacts")) {
            sendTtps('TA0035', 'Collection', 'T1636.003', 'Protected User Data: Contact List', 'ContentResolver.query', 'uri=' + uri.toString(), CONFIDENCE.HIGH);
        } else if (uri.toString().includes("sms")) {
            sendTtps('TA0035', 'Collection', 'T1636.004', 'Protected User Data: SMS Messages', 'ContentResolver.query', 'uri=' + uri.toString(), CONFIDENCE.HIGH);
            sendTtps('TA0034', 'Impact', 'T1582', 'SMS Control', 'ContentResolver.query', 'uri=' + uri.toString(), CONFIDENCE.HIGH);
        }
    }
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function (uri, projection, queryArgs, cancellationSignal) {
        hookContentResolverQuery(uri);
        return this.query(uri, projection, queryArgs, cancellationSignal);
    }
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
        hookContentResolverQuery(uri);
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    }
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function (uri, projection, selection, selectionArgs, sortOrder, cancellationSignal) {
        hookContentResolverQuery(uri);
        return this.query(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal);
    }

    // AccountManager
    const AccountManager = Java.use('android.accounts.AccountManager');
    AccountManager.getAccounts.implementation = function () {
        sendTtps('TA0035', 'Collection', 'T1636.005', 'Protected User Data: Accounts', 'AccountManager.getAccounts', '', CONFIDENCE.HIGH);
        return this.getAccounts();
    }

    // MediaProjectionManager
    const MediaProjection = Java.use('android.media.projection.MediaProjection');
    MediaProjection.createVirtualDisplay.overload('android.hardware.display.VirtualDisplayConfig', 'android.hardware.display.VirtualDisplay$Callback', 'android.os.Handler', 'android.content.Context').implementation = function (config, callback, handler, context) {
        sendTtps('TA0035', 'Collection', 'T1513', 'Screen Capture', 'MediaProjection.createVirtualDisplay', 'config=' + config, CONFIDENCE.HIGH);
        return this.createVirtualDisplay(config, callback, handler, context);
    }
    MediaProjection.createVirtualDisplay.overload('java.lang.String', 'int', 'int', 'int', 'int', 'android.view.Surface', 'android.hardware.display.VirtualDisplay$Callback', 'android.os.Handler').implementation = function (name, width, height, densityDpi, flags, surface, callback, handler) {
        sendTtps('TA0035', 'Collection', 'T1513', 'Screen Capture', 'MediaProjection.createVirtualDisplay', 'name=' + name + ', width=' + width + ', height=' + height, CONFIDENCE.HIGH);
        return this.createVirtualDisplay(name, width, height, densityDpi, flags, surface, callback, handler);
    }
    MediaProjection.createVirtualDisplay.overload('java.lang.String', 'int', 'int', 'int', 'boolean', 'android.view.Surface', 'android.hardware.display.VirtualDisplay$Callback', 'android.os.Handler').implementation = function (name, width, height, densityDpi, flags, surface, callback, handler) {
        sendTtps('TA0035', 'Collection', 'T1513', 'Screen Capture', 'MediaProjection.createVirtualDisplay', 'name=' + name + ', width=' + width + ', height=' + height, CONFIDENCE.HIGH);
        return this.createVirtualDisplay(name, width, height, densityDpi, flags, surface, callback, handler);
    }

    // HttpsUrlConnection
    const HttpsUrlConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsUrlConnection.setSSLSocketFactory.overload('javax.net.ssl.SSLSocketFactory').implementation = function (sf) {
        sendTtps('TA0037', 'Command and Control', 'T1521.003', 'Encrypted Channel: SSL Pinning', 'HttpsUrlConnection.setSSLSocketFactory', 'sf=' + sf, CONFIDENCE.HIGH);
        return this.setSSLSocketFactory(sf);
    }

    // HttpURLConnection
    const HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.getInputStream.implementation = function () {
        // sendTtps('TA0037', 'Command and Control', 'T1041', 'Exfiltration Over C2 Channel', 'HttpURLConnection.getInputStream', '', CONFIDENCE.MEDIUM);
        return this.getInputStream();
    }

    // RecoverySystem
    const RecoverySystem = Java.use('android.os.RecoverySystem');
    RecoverySystem.rebootWipeUserData.overload('android.content.Context').implementation = function (context) {
        sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'RecoverySystem.rebootWipeUserData', 'context=' + context, CONFIDENCE.HIGH);
        return this.rebootWipeUserData(context);
    }
    RecoverySystem.rebootWipeUserData.overload('android.content.Context', 'java.lang.String').implementation = function (context, reason) {
        sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'RecoverySystem.rebootWipeUserData', 'context=' + context + ', reason=' + reason, CONFIDENCE.HIGH);
        return this.rebootWipeUserData(context, reason);
    }
    RecoverySystem.rebootWipeUserData.overload('android.content.Context', 'boolean').implementation = function (context, shutdown) {
        sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'RecoverySystem.rebootWipeUserData', 'context=' + context + ', shutdown=' + shutdown, CONFIDENCE.HIGH);
        return this.rebootWipeUserData(context, shutdown);
    }
    RecoverySystem.rebootWipeUserData.overload('android.content.Context', 'boolean', 'java.lang.String', 'boolean').implementation = function (context, shutdown, reason, force) {
        sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'RecoverySystem.rebootWipeUserData', 'context=' + context + ', shutdown=' + shutdown + ', reason=' + reason + ', force=' + force, CONFIDENCE.HIGH);
        return this.rebootWipeUserData(context, shutdown, reason, force);
    }
    RecoverySystem.rebootWipeUserData.overload('android.content.Context', 'boolean', 'java.lang.String', 'boolean', 'boolean').implementation = function (context, shutdown, reason, force, wipeEuicc) {
        sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'RecoverySystem.rebootWipeUserData', 'context=' + context + ', shutdown=' + shutdown + ', reason=' + reason + ', force=' + force + ', wipeEuicc=' + wipeEuicc, CONFIDENCE.HIGH);
        return this.rebootWipeUserData(context, shutdown, reason, force, wipeEuicc);
    }

    // SmsManager
    const SmsManager = Java.use('android.telephony.SmsManager');
    function hookSendTextMessage() {
        sendTtps('TA0034', 'Impact', 'T1643', 'Generate Traffic from Victim', 'SmsManager.sendTextMessage', '', CONFIDENCE.HIGH);
        sendTtps('TA0034', 'Impact', 'T1582', 'SMS Control', 'SmsManager.sendTextMessage', '', CONFIDENCE.HIGH);
    }
    SmsManager.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent').implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
        hookSendTextMessage();
        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
    }
    SmsManager.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent', 'long').implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent, someLong) {
        hookSendTextMessage();
        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent, someLong);
    }
    SmsManager.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent', 'int', 'boolean', 'int').implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent, someInt1, someBoolean, someInt2) {
        hookSendTextMessage();
        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent, someInt1, someBoolean, someInt2);
    }
 
    // CookieManager
    const CookieManager = Java.use('android.webkit.CookieManager');
    CookieManager.getCookie.overload('java.lang.String').implementation = function (url) {
        sendTtps('TA0031', 'Credential Access', 'T1635', 'Steal Application Access Token', 'CookieManager.getCookie', 'url=' + url, CONFIDENCE.MEDIUM);
        return this.getCookie(url);
    }
});

// Concrete Classes ===========================================================================================================

Java.perform(function () {
    var hookedSet = new Set();

    function hookAccessibilityService() {
        Java.choose("android.accessibilityservice.AccessibilityService", {
            onMatch: function (instance) {
                if (hookedSet.has(instance.hashCode())) { return; }
                hookedSet.add(instance.hashCode());

                sendTtps('TA0031', 'Credential Access', 'T1453', 'Abuse Accessibility Features', 'AccessibilityService', 'instance=' + instance, CONFIDENCE.HIGH);
                instance.onAccessibilityEvent.implementation = function (accessibilityEvent) {
                    sendTtps('TA0030', 'Defense Evasion', 'T1516', 'Input Injection', 'AccessibilityService.onAccessibilityEvent', 'event=' + accessibilityEvent, CONFIDENCE.MEDIUM);
                    sendTtps('TA0031', 'Credential Access', 'T1417.001', 'Input Capture: Keylogging', 'AccessibilityService.onAccessibilityEvent', 'event=' + accessibilityEvent, CONFIDENCE.MEDIUM);
                    return this.onAccessibilityEvent(accessibilityEvent);
                }
            },
            onComplete: function () {
                setTimeout(hookAccessibilityService, 2000);
            }
        });
    }
    hookAccessibilityService();

    function hookCallRedirectionService() {
        // CallRedirectionService
        Java.choose("android.telecom.CallRedirectionService", {
            onMatch: function (instance) {
                if (hookedSet.has(instance.hashCode())) { return; }
                hookedSet.add(instance.hashCode());

                instance.onPlaceCall.implementation = function (phoneAccountHandle, intent) {
                    sendTtps('TA0035', 'Collection', 'T1616', 'Call Control', 'CallRedirectionService.onPlaceCall', 'intent=' + intent, CONFIDENCE.HIGH);
                    return this.onPlaceCall(phoneAccountHandle, intent);
                }
            },
            onComplete: function () {
                setTimeout(hookCallRedirectionService, 2000);
            }
        });
    }
    hookCallRedirectionService();

    function hookBroadcastReceiver() {
        // BroadcastReceiver
        Java.choose("android.content.BroadcastReceiver", {
            onMatch: function (instance) {
                if (hookedSet.has(instance.hashCode())) { return; }
                hookedSet.add(instance.hashCode());
                sendTtps('TA0028', 'Persistence', 'T1624.001', 'Event Triggered Execution: Broadcast Receivers', 'BroadcastReceiver.onReceive', '', CONFIDENCE.MEDIUM);
            },
            onComplete: function () {
                setTimeout(hookBroadcastReceiver, 2000);
            }
        });
    }
    hookBroadcastReceiver();
});

// Native =============================================================================================================================

Interceptor.attach(Module.findExportByName(null, 'execve'), {
    onEnter(args) {
        var fname = Memory.readCString(args[0]);
        var arg1 = Memory.readCString(args[1]);
        var arg2 = Memory.readCString(args[2]);

        sendTtps('TA0041', 'Execution', 'T1623.001', 'Command and Scripting Interpreter: Unix Shell', 'execve', 'fname=' + fname + ', arg1=' + arg1 + ', arg2=' + arg2, CONFIDENCE.HIGH)

        if (fname.includes('remount')) {
            sendTtps('TA0028', 'Persistence', 'T1645', 'Compromise Client Software Binary', 'execve', 'fname=' + fname + ', arg1=' + arg1 + ', arg2=' + arg2, CONFIDENCE.HIGH)
        }

        if (fname.includes('setenforce')) {
            sendTtps('TA0030', 'Defense Evasion', 'T1629.003', 'Impair Defenses: Disable or Modify Tools', 'execve', 'fname=' + fname + ', arg1=' + arg1 + ', arg2=' + arg2, CONFIDENCE.HIGH)
        }

        if (fname.includes('pm')) {
            if (arg1 === 'disable' && arg2.includes('com.google.android.gms.security.snet')) {
                sendTtps('TA0030', 'Defense Evasion', 'T1629.003', 'Impair Defenses: Disable or Modify Tools', 'execve', 'fname=' + fname + ', arg1=' + arg1 + ', arg2=' + arg2, CONFIDENCE.HIGH)
            }

            if (arg1 === 'uninstall') {
                sendTtps('TA0030', 'Defense Evasion', 'T1630.001', 'Indicator Removal on Host: Uninstall Malicious Application', 'execve', 'fname=' + fname + ', arg1=' + arg1 + ', arg2=' + arg2, CONFIDENCE.MEDIUM);
                sendTtps('TA0034', 'Impact', 'T1662', 'Data Destruction', 'execve', 'fname=' + fname + ', arg1=' + arg1 + ', arg2=' + arg2, CONFIDENCE.MEDIUM);
            }
        }

        if (fname.includes('ps')) {
            sendTtps('TA0032', 'Discovery', 'T1424', 'Process Discovery', 'execve', 'fname=' + fname, CONFIDENCE.HIGH);
        }
    },
    onLeave(result) {
    }
});

Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter(args) {
        var O_WRONLY = 0x1;
        var O_RDWR = 0x2;
        var O_CREAT = 0x40;
        var O_APPEND = 0x400;

        var fname = args[0].readUtf8String();
        var flags = args[1]

        if (fname.includes('app_webview')) return;

        if (fname.includes('.apk') && fname.includes('.dex')) {
            if ((flags & (O_CREAT | O_WRONLY | O_RDWR | O_APPEND)) !== 0) {
                sendTtps('TA0028', 'Persistence', 'T1577', 'Compromise Application Executable', fname, CONFIDENCE.MEDIUM)
            }
        }

        if (fname.includes('.apk') && !fname.includes('stub.apk') && (flags & (O_CREAT | O_WRONLY | O_RDWR)) !== 0) {
            sendTtps('TA0028', 'Persistence', 'T1645', 'Compromise Client Software Binary', 'open', 'fname=' + fname + ', flags=' + flags, CONFIDENCE.MEDIUM)
        }

        if (fname.includes('.nomedia')) {
            sendTtps('TA0030', 'Defense Evasion', 'T1628.003', 'Hide Artifacts: Conceal Multimedia Files', 'open', 'fname=' + fname + ', flags=' + flags, CONFIDENCE.HIGH);
        }

        if (fname.includes('.pdf') || fname.includes('.doc') || fname.includes('.docx') ||
            fname.includes('.ppt') || fname.includes('.pptx') ||
            fname.includes('.xls') || fname.includes('.xlsx') ||
            fname.includes('.jpg') || fname.includes('.jpeg') ||
            fname.includes('.mp4') || fname.includes('.html') ||
            fname.includes('.png') || fname.includes('.db') ||
            fname.includes('.mp4')
        ) {
            sendTtps('TA0035', 'Collection', 'T1533', 'Data from Local System', 'open', 'fname=' + fname + ', flags=' + flags, CONFIDENCE.MEDIUM);
        }

        if ((fname.includes('/sdcard') || fname.includes('/storage')) && (flags & (O_CREAT | O_WRONLY | O_RDWR)) !== 0) {
            sendTtps('TA0035', 'Collection', 'T1409', 'Stored Application Data', 'open', 'fname=' + fname + ', flags=' + flags, CONFIDENCE.MEDIUM);
        }


        if ((fname.includes('.apk') || fname.includes('.jar') || fname.includes('.dex') || fname.includes('.so')) && (flags & (O_CREAT | O_WRONLY | O_RDWR)) !== 0) {
            sendTtps('TA0037', 'Command and Control', 'T1577', 'Ingress Tool Transfer', 'open', 'fname=' + fname + ', flags=' + flags, CONFIDENCE.MEDIUM)
        }
    },
    onLeave(result) {
    }
})

Interceptor.attach(Module.findExportByName(null, 'access'), {
    onEnter(args) {
        var fname = args[0].readUtf8String();

        if (fname.includes('/proc')) {
            sendTtps('TA0032', 'Discovery', 'T1420', 'File and Directory Discovery', 'access', 'fname=' + fname, CONFIDENCE.HIGH);
        }
    },
    onLeave(result) {
    }
});


Interceptor.attach(Module.findExportByName(null, 'setuid'), {
    onEnter(args) {
        var uid = args[0].toInt32();
        if (uid === 0) {
            sendTtps('TA0029', 'Privilege Escalation', 'T1404', 'Device Administrator Permissions', 'setuid', 'uid=' + uid, CONFIDENCE.HIGH);
        }
    },
    onLeave(result) {
    }
})

Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
    onEnter(args) {
        var PTRACE_SETREGS = 0x0c;
        var PTRACE_POKETEXT = 0x4;
        var PTRACE_POKEDATA = 0x5;

        var op = args[0].toInt32();

        if (op === PTRACE_SETREGS || op === PTRACE_POKETEXT || op === PTRACE_POKEDATA) {
            sendTtps('TA0029', 'Privilege Escalation', 'T1631.001', 'Process Injection: Ptrace System Calls', 'ptrace', 'op=' + op, CONFIDENCE.HIGH);
        }

    },
    onLeave(result) {
    }
})

Interceptor.attach(Module.findExportByName(null, 'unlink'), {
    onEnter(args) {
        var fname = args[0].readUtf8String();

        if (fname.includes('profileInstalled')) return;
        if (fname.includes('androidx.work.workdb-journal')) return;
        if (fname.includes('shared_prefs')) return;
        if (fname.includes('app_webview')) return;

        sendTtps('TA0030', 'Defense Evasion', 'T1630.002', 'Indicator Removal on Host: File Deletion', 'unlink', 'fname=' + fname, CONFIDENCE.LOW);
    },
    onLeave(result) {
    }
})

Interceptor.attach(Module.findExportByName(null, 'rename'), {
    onEnter(args) {
        var fname = args[0].readUtf8String();

        if (fname === 'su') {
            sendTtps('TA0030', 'Defense Evasion', 'T1630.003', 'Indicator Removal on Host: Disguise Root/Jailbreak Indicators', 'rename', 'fname=' + fname, CONFIDENCE.HIGH);
        }
    },
    onLeave(result) {
    }
})

Interceptor.attach(Module.findExportByName(null, '__system_property_get'), {
    onEnter(args) {
        var prop = args[0].readUtf8String();

        if (prop === 'ro.kernel.qemu' ||
            prop === 'ro.product.model' ||
            prop === 'ro.product.manufacturer' ||
            prop === 'ro.build.fingerprint' ||
            prop === 'ro.build.flavor' ||
            prop === 'ro.serialno'
        ) {
            sendTtps('TA0030', 'Defense Evasion', 'T1633.001', 'Virtualization/Sandbox Evasion: System Checks', '__system_property_get', prop, CONFIDENCE.LOW);
            sendTtps('TA0032', 'Discovery', 'T1426', 'System Information Discovery', '__system_property_get', prop, CONFIDENCE.HIGH);
        }
        if (prop === "ro.build.fingerprint" ||
            prop === "ro.build.version.release" ||
            prop === "ro.build.version.sdk" ||
            prop === "ro.build.id" ||
            prop === "ro.build.display.id" ||
            prop === "ro.build.product" ||
            prop === "ro.build.manufacturer" ||
            prop === "ro.build.brand" ||
            prop === "ro.build.model" ||
            prop === "ro.build.device" ||
            prop === "ro.build.tags" ||
            prop === "ro.build.type" ||
            prop === "ro.product.name" ||
            prop === "ro.product.device" ||
            prop === "ro.product.board" ||
            prop === "ro.product.cpu.abi" ||
            prop === "ro.product.cpu.abilist" ||
            prop === "ro.product.manufacturer" ||
            prop === "ro.product.model" ||
            prop === "ro.serialno" ||
            prop === "ro.boot.serialno" ||
            prop === "ro.boot.hardware" ||
            prop === "ro.hardware" ||
            prop === "ro.board.platform" ||
            prop === "ro.kernel.qemu" ||
            prop === "ro.boot.vbmeta.device_state" ||
            prop === "ro.boot.verifiedbootstate" ||
            prop === "ro.boot.flash.locked" ||
            prop === "ro.debuggable" ||
            prop === "ro.secure") {
            sendTtps('TA0032', 'Discovery', 'T1426', 'System Information Discovery', '__system_property_get', prop, CONFIDENCE.HIGH);
        }
    },
    onLeave(result) {
    }
})

function hook_connect(sockRemote) {
    sendTtps('TA0032', 'Discovery', 'T1423', 'Network Service Scanning', 'connect', sockRemote.ip + ':' + sockRemote.port, CONFIDENCE.LOW)
    if (sockRemote.port === 80 || sockRemote.port === 443) {
        sendTtps('TA0037', 'Command and Control', 'T1437.001', 'Application Layer Protocol: Web Protocols', 'connect', sockRemote.ip + ':' + sockRemote.port, CONFIDENCE.HIGH)
    } else {
        sendTtps('TA0037', 'Command and Control', 'T1437', 'Application Layer Protocol', 'connect', sockRemote.ip + ':' + sockRemote.port, CONFIDENCE.HIGH)
    }

    if (sockRemote.port !== 21 && sockRemote.port !== 22 && sockRemote.port !== 25 && sockRemote.port !== 53 &&
        sockRemote.port !== 80 && sockRemote.port !== 110 && sockRemote.port !== 143 && sockRemote.port !== 443 &&
        sockRemote.port !== 445 && sockRemote.port !== 500 && sockRemote.port !== 587 && sockRemote.port !== 993 &&
        sockRemote.port !== 5223 && sockRemote.port !== 5228) {
        sendTtps('TA0037', 'Command and Control', 'T1509', 'Non-Standard Port', 'connect', sockRemote.ip + ':' + sockRemote.port, CONFIDENCE.HIGH)
    }

    if (sockRemote.port === 20 || sockRemote.port === 21 || sockRemote.port === 53) {
        sendTtps('TA0036', 'Exfiltration', 'T1639.001', 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol', sockRemote.ip + ':' + sockRemote.port, CONFIDENCE.MEDIUM)
    }
    sendTtps('TA0036', 'Exfiltration', 'T1639', 'Exfiltration Over Alternative Protocol', 'connect', sockRemote.ip + ':' + sockRemote.port, CONFIDENCE.LOW)
    sendTtps('TA0036', 'Exfiltration', 'T1646', 'Exfiltration Over C2 Channel', 'connect', sockRemote.ip + ':' + sockRemote.port, CONFIDENCE.MEDIUM)

}

Interceptor.attach(Module.getExportByName(null, "connect"), {
    onEnter(args) {
        this.sockFd = args[0].toInt32()
        this.addrPtr = args[1]
        this.addrLen = args[2].toInt32()

        // Parse address from sockaddr structure
        if (this.addrPtr && !this.addrPtr.isNull()) {
            const sa_family = this.addrPtr.readU16()

            if (sa_family === 2) { // AF_INET (IPv4)
                const port = ((this.addrPtr.add(2).readU8() << 8) | this.addrPtr.add(3).readU8())
                const ip = this.addrPtr.add(4).readU8() + '.' +
                    this.addrPtr.add(5).readU8() + '.' +
                    this.addrPtr.add(6).readU8() + '.' +
                    this.addrPtr.add(7).readU8()
                this.remoteAddr = { ip: ip, port: port }
                hook_connect(this.remoteAddr);
            } else if (sa_family === 10) { // AF_INET6 (IPv6)
                const port = ((this.addrPtr.add(2).readU8() << 8) | this.addrPtr.add(3).readU8())
                // parse IPv6 address
                const ipParts = []
                for (let i = 0; i < 8; i++) {
                    const part = this.addrPtr.add(8 + i * 2).readU16().toString(16)
                    ipParts.push(part)
                }
                let ip = ipParts.join(':')

                // ipv6 to ipv4 mapping like 0:0:0:0:0:ffff:d7b9:1f71 -> 215.185.31.113
                if (ip.startsWith('0:0:0:0:0:ffff:') || ip.startsWith('::ffff:')) {
                    const lastTwo = ipParts.slice(-2)
                    const hex1 = parseInt(lastTwo[0], 16)
                    const hex2 = parseInt(lastTwo[1], 16)
                    const ipv4 = `${(hex1 >> 8) & 0xff}.${hex1 & 0xff}.${(hex2 >> 8) & 0xff}.${hex2 & 0xff}`
                    ip = ipv4
                }

                this.remoteAddr = { ip: ip, port: port }
                hook_connect(this.remoteAddr);
            }
        }
    },
    onLeave(res) { }
})

Interceptor.attach(Module.findExportByName(null, "sendto"), {
    onEnter(args) {
        this.sockFd = args[0].toInt32()
        this.buffer = args[1]
        this.bufferLen = args[2].toInt32()
        this.flags = args[3].toInt32()
        this.addrPtr = args[4]
        this.addrLen = args[5].toInt32()
    },
    onLeave(res) {
        const sockType = Socket.type(this.sockFd)
        if (sockType !== "tcp" && sockType !== "tcp6") return

        const sockLocal = Socket.localAddress(this.sockFd)
        const sockRemote = Socket.peerAddress(this.sockFd)

        const message = Memory.readCString(this.buffer, this.bufferLen);
        if (message.includes("Host: twitter.com") || message.includes("Host: google.com") || message.includes("Host: facebook.com") ||
            message.includes("Host: instagram.com") || message.includes("Host: linkedin.com")) {
            sendTtps('TA0037', 'Command and Control', 'T1481', 'Web Service', 'sendto', message, CONFIDENCE.HIGH)
        }
    }
});

Interceptor.attach(Module.findExportByName("libssl.so", "SSL_write"), {
    onEnter: function (args) {
        const message = Memory.readCString(args[1], args[2].toInt32());
        if (message.includes("Host: twitter.com") || message.includes("Host: google.com") || message.includes("Host: facebook.com") ||
            message.includes("Host: instagram.com") || message.includes("Host: linkedin.com")) {
            sendTtps('TA0037', 'Command and Control', 'T1481', 'Web Service', 'sendto', message, CONFIDENCE.HIGH)
        }
    }
});

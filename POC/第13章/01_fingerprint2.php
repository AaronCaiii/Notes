<!doctype html>
<html>
<head>
<title>Fingerprintjs2 test</title>
</head>
<body>
<h1>Fingerprintjs2</h1>
<p>Your browser fingerprint: <strong id="fp"></strong></p>
<p><code id="time" /></p>
<p><span id="details" /></p>
**<script src="fingerprint2.js"></script>**
<script>
var d1 = new Date();
var options = {};
**Fingerprint2.get(options, function (components) {
    // 库返回的components变量是一个包含从客户端提取的所有信息的数组
    var values = components.map(function (component) { return component.value; });
    var murmur = Fingerprint2.x64hash128(values.join(''), 31);
    //存储在components数组中的值被传递给murmur哈希函数，以便创建浏览器的哈希指纹**
    var d2 = new Date();
    var timeString = "Time to calculate the fingerprint: " + (d2 - d1) + "ms";
    var details = "<strong>Detailed information: </strong><br />";
    if (typeof window.console !== "undefined") {
        **for (var index in components) {
            var obj = components[index];
            var value = obj.value;**
            if (value !== null) {
                **var line = obj.key + " = " + value.toString().substr(0, 150);
                details += line + "<br />";**
            }
        }
}
**document.querySelector("#details").innerHTML = details;
document.querySelector("#fp").textContent = murmur;
document.querySelector("#time").textContent = timeString;**
});
</script>
</body>
</html>

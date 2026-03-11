<html>
<head>
<title>About ip2geo.org</title>
<link rel="stylesheet" type="text/css" href="style.css" />
</head>
<body>
<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

  ga('create', 'UA-102801602-1', 'auto');
  ga('send', 'pageview');

</script>
<div class="content">
<h1>About ip2geo.org</h1>
<h3>Panic!</h3>
<p>Being on the receiving end of a distributed penetration probe &mdash; whether it is aimed at your email system, shell login, or any other public-facing service &mdash; can be a harrowing experience. Things get hectic, and the tools avaialble don't always help narrow down malicious connections, let alone format their output in a prepackaged way to highlight strange connections</p>
<h3>Frustration!</h3>
<p>So you take the output from the powerful CLI tool and put it in your choice of power-text editor, spend precious minutes cleaning it up, and then ... they want you to copy paste IP addresses into a web form, one by one? Don't they know you have tens, hundreds, maybe thousands of entries to check? There isn't time for this nonsense.</p>
<h3>Solution!</h3>
<p>I was supporting an old system that ran email for several thousand users, had no password policies, and generally had no support. Email accounts were being compromised regularly, but I didn't have the budget (either cash or man hours) to really fix the problem. Instead, I put this tool together to take raw output from netstat, fail2ban logs, or any other copy/paste text source and not only clean it for me, but do a fast lookup to see where these IPs were coming from. Suddenly it was easy to see the botnet poking at logins from all across the world &mdash; and drop traffic from them.</p>
<h3>Wait, what happenedi?</h3>
<p>ip2geo.org takes any text input and combs through looking for patterns that match valid IPv4 addresses. It then checks them against an IP-to-geolocation database and returns results. You can filter out certain countries to raise the <acronym title="Signal to Noise Ratio">SNR</acronym> (say, removing all US IPs when hunting for traffic that doesn't make sense to your Montana business's website).</p>
<h3>Why is it free?</h3>
<p>I used free tools to create it. Mostly it's free because I wish this existed for free when I needed it. Please donate to help with hosting if you find it useful.</p>
<p><a href="/">Back to ip2geo.org</a></p>
</div>
<link href="https://fonts.googleapis.com/css?family=Open+Sans" rel="stylesheet">
</body>
</html>

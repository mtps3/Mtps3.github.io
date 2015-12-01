---
layout: page
title: Meetings
permalink: /meetings/
---

<ul>
{% for post in site.categories.meeting %}
<li>{{ post.when }} <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>
{% endfor %}
</ul>

**IMPORTANT:**
All our meetings are open to everyone, so if you are not part of LosFuzzys, feel free to come anyway. And if you know some people interested in what we do, please invite them. :-)


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})

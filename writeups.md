---
layout: page
title: Writeups
permalink: /writeups/
---

<span class="discreet">Sort by <a href="/tags">tag</a>, <a href="/authors">author</a></span>

{% for post in site.categories.writeup %}
   {% capture this_year %}{{ post.date | date: "%Y" }}{% endcapture %}
   {% capture next_year %}{{ post.next.date | date: "%Y" }}{% endcapture %}

   {% if forloop.first %}
<h3>{{this_year}}</h3>
<ul>
   {% endif %}

<li><!--{{ post.date | date: "%b %-d, %Y" }} --> <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>
    # {% else %}
   {% if this_year != next_year %}
</ul>
<h3>{{next_year}}</h3>
<ul>
        #{% endif %}
   {% endif %}

   {% if forloop.last %}
</ul>
   {% endif %}
{% endfor %}


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})

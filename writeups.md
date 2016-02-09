---
layout: page
title: Writeups
permalink: /writeups/
---

<ul>
{% for post in site.categories.writeup %}
   {% capture this_year %}{{ post.date | date: "%Y" }}{% endcapture %}
   {% capture next_year %}{{ post.next.date | date: "%Y" }}{% endcapture %}

   {% if forloop.first %}
<li>{{this_year}}
   <ul>
    {% else %}
        {% if this_year != next_year %}
   </ul>
</li>
<li>{{this_year}}
        <ul>
        {% endif %}
    {% endif %}

      <li><!--{{ post.date | date: "%b %-d, %Y" }} --> <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>

   {% if forloop.last %}
      </ul>
</li>
   {% endif %}

{% endfor %}
</ul>


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})

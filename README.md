# juntools
A script that parses an Juniper SRX FW configuration (in XML format) and via Dot, using pydot, create graphs to vizualize relationships between policies, services and security zones.

I created this project back in 2012 when Juniper didn't have a good MGMT tool (pre-Space) and i wanted a way to visualize a pretty complicated setup in regards to security/NAT policies and security zones.

Required Python modules:
* `pydot` (and Graphviz binaries)
* `BeautifulSoup` (the one used in this case is pre-bs4)

### Example

```python
from juntools import jViz

viz = jViz("juniper-config-file.xml", verbose=True)

viz.parse_conf('<policies>','</policies>')
policies, zones = viz.getpolicies()
viz.create_graph(zone,direction,gdir='/root/bin/gviz/')

viz.get_fwinfo()
viz.close_conf()
```

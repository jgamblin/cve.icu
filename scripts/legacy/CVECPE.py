#!/usr/bin/env python
# coding: utf-8

# # CPE Data
# ---

# In[1]:


# Import necessary libraries
import glob
import json
import pandas as pd
from itables import show, init_notebook_mode
from IPython.display import Markdown
import itables.options as opt
import matplotlib.pyplot as plt
import datetime

# Initialize itables options
opt.dom = "tpir"
opt.style = "table-layout:auto;width:auto"
init_notebook_mode(all_interactive=True, connected=True)


# In[2]:


row_accumulator = []

for filename in glob.glob('nvd.jsonl'):
    with open(filename, 'r', encoding='utf-8') as f:
        nvd_data = json.load(f)
        for entry in nvd_data:
            if 'configurations' in entry['cve']:
                for config in entry['cve']['configurations']:
                    for node in config['nodes']:
                        if 'cpeMatch' in node:
                            for cpe in node['cpeMatch']:
                                if cpe['vulnerable']:
                                    cve = entry['cve']['id']
                                    published_date = entry['cve'].get('published', 'Missing_Data')
                                    cpe_string = cpe['criteria']
                                    end = cpe.get('versionEndExcluding', 'None')
                                    end2 = cpe.get('versionEndIncluding', 'None')
                                    start = cpe.get('versionStartExcluding', 'None')
                                    start2 = cpe.get('versionStartIncluding', 'None')

                                    new_row = {
                                        'CVE': cve,
                                        'Published': published_date,
                                        'CPE': cpe_string,
                                        'StartI': start,
                                        'StartE': start2,
                                        'EndI': end,
                                        'EndE': end2
                                    }
                                    row_accumulator.append(new_row)

nvd = pd.DataFrame(row_accumulator)
nvd['Published'] = pd.to_datetime(nvd['Published'], errors='coerce')
thisyear = (nvd['Published'] > '2000-01-01') & (nvd['Published'] < '2026-01-01')
nvd = nvd.loc[thisyear]
nvd = nvd.sort_values(by=['Published'])


# ## CPE Data

# ### CVEs With Most CPEs

# In[3]:


# Calculate the counts of CVEs
cve_counts = nvd['CVE'].value_counts().reset_index()
cve_counts.columns = ['CVE', 'Count']

# Display the top 20 CVEs
show(cve_counts.head(20), scrollCollapse=True, paging=False)


# ### Most Common CPEs

# In[4]:


# Calculate the counts of CPEs
cpe_counts = nvd['CPE'].value_counts().reset_index()
cpe_counts.columns = ['CPE', 'Count']

# Display the top 20 CPEs
show(cpe_counts.head(20), scrollCollapse=True, paging=False)


# ### Number of CPEs

# In[5]:


# Calculate the number of unique CPEs
unique_cpes = nvd['CPE'].nunique()

# Calculate the total number of CVEs
total_cves = nvd['CVE'].nunique()

# Create a sentence with the information, adding commas to the numbers
sentence = f"There are {unique_cpes:,} unique CPEs across {total_cves:,} total CVEs."

# Display the sentence
print(sentence)


# In[6]:


Markdown(f"This report is updated automatically every day, last generated on: **{datetime.datetime.now()}**")


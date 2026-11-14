import sys,os,json,glob,traceback
CAT={c['id']:c for c in json.load(open('cis/catalog_latest.json'))}
from concurrent.futures import ProcessPoolExecutor
sys.path.insert(0,'cis'); import parse_cis_pdf as P
def one(pdf):
    import re
    wb=int(os.path.basename(pdf)[:-4])
    try:
        meta,recs=P.parse(pdf,wb)
        cat=CAT.get(wb)
        if cat:  # название и версия из каталога WorkBench надёжнее, чем с обложки PDF
            meta["title_in_pdf"]=meta["title"]; meta["title"]=cat["title"]; meta["version"]=cat["version"].lstrip("vV")
            meta["community"]=cat.get("community"); meta["collection"]=cat.get("collection") or None
            for r in recs: r["benchmark"]=meta["title"]; r["benchmark_version"]=meta["version"]
        seen={}
        for r in recs:  # в части STIG-бенчмарков номера повторяются в самом PDF
            k=seen.get(r["id"],0); seen[r["id"]]=k+1
            if k: r["uid"]+=f"#{k+1}"; r["duplicate_number_in_source"]=True
        slug=P.slugify(re.sub(r"^CIS ","",meta["title"]))+(("-v"+re.sub(r"[^0-9a-zA-Z.]+","-",meta["version"]).strip("-").lower()) if meta["version"] else "")
        d=os.path.join('cis/benchmarks',slug); 
        if os.path.exists(d): d+=f'-{wb}'; slug+=f'-{wb}'
        os.makedirs(d,exist_ok=True); meta["slug"]=slug
        json.dump(meta,open(d+'/benchmark.json','w'),ensure_ascii=False,indent=1)
        with open(d+'/recommendations.jsonl','w') as f:
            for r in recs: f.write(json.dumps(r,ensure_ascii=False)+'\n')
        return wb,slug,len(recs),meta['recommendations_in_pdf_outline'],len(meta['parse_warnings']),None
    except Exception as e:
        return wb,None,0,None,0,repr(e)[:200]
if __name__=='__main__':
    pdfs=sorted(glob.glob('cis/pdf/*.pdf'))
    with ProcessPoolExecutor(6) as ex: res=list(ex.map(one,pdfs))
    print('done',len(res),'errors',sum(1 for r in res if r[5]),'zero',sum(1 for r in res if r[2]==0),'recs',sum(r[2] for r in res))
    idx=[]
    for d in sorted(glob.glob('cis/benchmarks/*/')):
        m=json.load(open(d+'benchmark.json')); n=sum(1 for _ in open(d+'recommendations.jsonl'))
        idx.append({'workbench_id':m['workbench_id'],'slug':m['slug'],'title':m['title'],'version':m['version'],'published':m['published'],
                    'community':m.get('community'),'collection':m.get('collection'),'pages':m['pages'],'recommendations':n,
                    'automated':m['counts']['automated'],'manual':m['counts']['manual'],'sections':len(m['sections']),
                    'parse_warnings':len(m['parse_warnings']),'path':d.replace('cis/','')+'recommendations.jsonl','source_url':m['source_url']})
    json.dump(idx,open('cis/benchmarks/index.json','w'),ensure_ascii=False,indent=1)
    print('index',len(idx))


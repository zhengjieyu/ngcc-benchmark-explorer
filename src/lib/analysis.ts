export type Measurement = {cycles:number;seconds:number|null;source_file:string;kat:string|null;kat_not_passed:boolean;build_flags:string|null};
export type RecordRow = {id:string;candidate_id:string;algorithm:string;type:'KEM'|'Signature';parameter_set:string;implementation:string;platform:string;hardware:string;architecture:string;security_group:string|null;security_group_origin:'target-table'|'specification'|null;security_target_instance:string|null;security_target_match:string;security_note:string;spec_classical_target_bits:number|null;spec_claim_source:string|null;spec_claim_note:string|null;category:string|null;assumption:string|null;classification_source:string|null;source_directory:string|null;candidate_directory:string;build_profile:string|null;build_flags:string|null;public_key_bytes:number|null;secret_key_bytes:number|null;ciphertext_bytes:number|null;shared_secret_bytes:number|null;signature_bytes:number|null;size_basis:string|null;measurements:Record<string,Measurement>;missing:{metric:string;reason:string;source_file?:string}[];source_commit:string;metadata_sources:string[]};
export type Metric = 'public_key_bytes'|'secret_key_bytes'|'ciphertext_bytes'|'signature_bytes'|'pk_ct_bytes'|'pk_sig_bytes'|'keygen_cycles'|'encap_cycles'|'decap_cycles'|'sign_cycles'|'verify_cycles';
export const metricLabel:Record<Metric,string>={public_key_bytes:'Public key · B',secret_key_bytes:'Secret key · B',ciphertext_bytes:'Ciphertext · B',signature_bytes:'Signature · B',pk_ct_bytes:'Public key + ciphertext · B',pk_sig_bytes:'Public key + signature · B',keygen_cycles:'Keygen · cycles',encap_cycles:'Encapsulation · cycles',decap_cycles:'Decapsulation · cycles',sign_cycles:'Signing · cycles',verify_cycles:'Verification · cycles'};
export const kemMetrics:Metric[]=['pk_ct_bytes','public_key_bytes','secret_key_bytes','ciphertext_bytes','keygen_cycles','encap_cycles','decap_cycles'];
export const sigMetrics:Metric[]=['pk_sig_bytes','public_key_bytes','secret_key_bytes','signature_bytes','keygen_cycles','sign_cycles','verify_cycles'];
export function value(r:RecordRow,m:Metric):number|null { if(m==='pk_ct_bytes') return r.public_key_bytes!=null&&r.ciphertext_bytes!=null?r.public_key_bytes+r.ciphertext_bytes:null; if(m==='pk_sig_bytes') return r.public_key_bytes!=null&&r.signature_bytes!=null?r.public_key_bytes+r.signature_bytes:null; if(m.endsWith('_cycles')) return r.measurements[m]?.cycles??null; return r[m as keyof RecordRow] as number|null; }
export function dominates(a:[number,number],b:[number,number]):boolean{return a[0]<=b[0]&&a[1]<=b[1]&&(a[0]<b[0]||a[1]<b[1]);}
export function frontier<T>(items:T[],coords:(item:T)=>[number,number]):T[]{return items.filter((p,i)=>!items.some((q,j)=>i!==j&&dominates(coords(q),coords(p))));}
export type RangeBounds={min?:string;max?:string};
export type RangeFilters=Record<string,RangeBounds>;
export function filterMetricValue(r:RecordRow,metric:string):number|null{
  if(metric.endsWith('_ms')) return r.measurements[metric.replace('_ms','_cycles')]?.seconds!=null?r.measurements[metric.replace('_ms','_cycles')].seconds!*1000:null;
  if(metric in metricLabel) return value(r,metric as Metric);
  return null;
}
export function observedRanges(rows:RecordRow[],type:'KEM'|'Signature',keys:string[]):RangeFilters{
  const subset=rows.filter(r=>r.type===type);
  return Object.fromEntries(keys.map(key=>{
    const values=subset.map(r=>filterMetricValue(r,key)).filter((n):n is number=>n!=null&&Number.isFinite(n));
    if(!values.length)return [key,{min:'',max:''}];
    const min=Math.min(...values),max=Math.max(...values);
    const scale=key.endsWith('_ms')?1_000_000:1;
    return [key,{min:String(Math.floor(min*scale)/scale),max:String(Math.ceil(max*scale)/scale)}];
  }));
}
export function changedRangeBounds(current:RangeFilters,defaults:RangeFilters):RangeFilters{
  return Object.fromEntries(Object.entries(current).map(([key,b])=>[key,{
    min:String(b.min??'')===String(defaults[key]?.min??'')?'':b.min,
    max:String(b.max??'')===String(defaults[key]?.max??'')?'':b.max
  }]));
}
export function inRanges(r:RecordRow,ranges:RangeFilters):boolean{return Object.entries(ranges).every(([metric,b])=>{const min=String(b.min??'').trim(),max=String(b.max??'').trim();if(!min&&!max)return true;const n=filterMetricValue(r,metric);if(n==null)return false;return (!min||n>=Number(min))&&(!max||n<=Number(max));});}
export function targetFilterKey(r:RecordRow):string{return r.security_group??(r.spec_classical_target_bits?`spec-${r.spec_classical_target_bits}`:'spec-unclassified');}
export function filterRows(rows:RecordRow[],f:{type:'KEM'|'Signature';security:string;platform:string;implementation:string;algorithm:string;category?:string;algorithms?:string[];securityGroups?:string[];ranges?:RangeFilters}):RecordRow[]{return rows.filter(r=>r.type===f.type&&(f.security==='all'||r.security_group===f.security)&&(f.platform==='all'||r.platform===f.platform)&&(f.implementation==='all'||r.implementation===f.implementation)&&(f.algorithm==='all'||r.algorithm===f.algorithm)&&(!f.category||f.category==='all'||r.category===f.category)&&(!f.algorithms||f.algorithms.includes(r.algorithm))&&(!f.securityGroups||f.securityGroups.includes(targetFilterKey(r)))&&(!f.ranges||inRanges(r,f.ranges)));}
// A flag repeated verbatim does not change the build. Drop the repeat unless a conflicting flag with the same
// option name (e.g. another -std= or -O level) sits between the two copies, where the repeat decides the result.
const flagOption=(t:string)=>t.includes('=')?t.slice(0,t.indexOf('=')):/^-O/.test(t)?'-O':t;
export function normalizeFlags(flags:string|null):string|null{if(flags==null)return null;const tokens=flags.trim().split(/\s+/).filter(Boolean);return tokens.filter((t,i)=>{const j=tokens.indexOf(t);return j===i||tokens.slice(j+1,i).some(u=>u!==t&&flagOption(u)===flagOption(t));}).join(' ');}
export function comparisonKey(r:RecordRow):string{return [r.security_group,r.platform,r.hardware,r.implementation,r.build_profile,normalizeFlags(r.build_flags)].join('|');}
export function comparable(r:RecordRow,x:Metric,y:Metric):boolean{return !!r.security_group&&[x,y].every(m=>value(r,m)!=null&&(!m.endsWith('_cycles')||!r.measurements[m]?.kat_not_passed));}
export function dominatorsByGroup(rows:RecordRow[],x:Metric,y:Metric):Map<string,RecordRow[]>{const result=new Map<string,RecordRow[]>();const eligible=rows.filter(r=>comparable(r,x,y));for(const r of eligible){const key=comparisonKey(r),point:[number,number]=[value(r,x)!,value(r,y)!];result.set(r.id,eligible.filter(other=>other.id!==r.id&&comparisonKey(other)===key&&dominates([value(other,x)!,value(other,y)!],point)));}return result;}
export function paretoGroups(rows:RecordRow[],x:Metric,y:Metric):Set<string>{const groups=new Map<string,RecordRow[]>();for(const r of rows){if(!comparable(r,x,y))continue;const k=comparisonKey(r);groups.set(k,[...(groups.get(k)??[]),r]);}const result=new Set<string>();for(const group of groups.values())for(const r of frontier(group,z=>[value(z,x)!,value(z,y)!]))result.add(r.id);return result;}

export function paretoTiersByGroup(rows:RecordRow[],x:Metric,y:Metric):Map<string,number>{
  const groups=new Map<string,RecordRow[]>();
  for(const r of rows){if(!comparable(r,x,y))continue;const key=comparisonKey(r);groups.set(key,[...(groups.get(key)??[]),r]);}
  const tiers=new Map<string,number>();
  for(const group of groups.values()){
    let remaining=group;
    let tier=1;
    while(remaining.length){
      const current=frontier(remaining,r=>[value(r,x)!,value(r,y)!]);
      for(const r of current)tiers.set(r.id,tier);
      const ids=new Set(current.map(r=>r.id));
      remaining=remaining.filter(r=>!ids.has(r.id));
      tier++;
    }
  }
  return tiers;
}

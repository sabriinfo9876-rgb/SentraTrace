import { jsPDF } from 'jspdf'
import { Download } from 'lucide-react'
import { useApp } from '../context/AppContext'
import { Head } from '../components/Table'
export default function Reports(){
 const {stats,events,notify}=useApp()
 const make=()=>{if(!stats)return;const d=new jsPDF();let y=22;const line=(t:string,s=10,b=false)=>{if(y>280){d.addPage();y=20}d.setFontSize(s);d.setFont('helvetica',b?'bold':'normal');for(const part of d.splitTextToSize(t,180)){if(y>280){d.addPage();y=20}d.text(part,14,y);y+=s*.45}y+=3}
  line('SentraTrace Security Report',20,true);line(`Generated ${new Date().toLocaleString()}`);y+=4
  line('Summary',14,true);line(`Recorded decisions: ${stats?.total_requests}`);line(`Safe requests: ${stats?.safe_requests}`);line(`Risk detections: ${stats?.threats_detected}`);line(`Blocked decisions: ${stats?.blocked_attacks}`);y+=4
  line('Incidents',14,true);events.forEach(e=>{line(`${e.id}  ${e.source}  ${e.type}  risk ${e.risk}  ${e.status}`,10,true);line(`${e.user} -> ${e.resource}`);line(`Why: ${e.reason}`);line(`Fix: ${e.recommendation}`);y+=2})
  d.save('sentratrace-report.pdf');notify('Report downloaded')}
 return <><Head t="Reports" s="Download a PDF of current stats, incidents and fixes. It is generated in your browser."/>
 <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{[['Requests',stats?.total_requests],['Safe',stats?.safe_requests],['Threats',stats?.threats_detected],['Blocked',stats?.blocked_attacks]].map(([k,v])=><div key={k as string} className="nc min-w-0 p-4 sm:p-6"><div className="text-sm text-muted">{k}</div><div className="mt-2 break-words font-serif text-3xl sm:text-4xl">{(v as number|undefined)?.toLocaleString()}</div></div>)}</div>
 <p className="mt-8 text-muted">{events.length} recent records will be included.</p><button disabled={!stats} onClick={make} className="mt-4 flex items-center gap-2 rounded-md bg-accent px-4 py-3 font-semibold sm:px-5"><Download size={16} strokeWidth={1.5}/>Download PDF</button></>}

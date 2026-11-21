import { useState } from 'react'
import { useLocation, useSearchParams } from 'react-router-dom'
import { useApp } from '../context/AppContext'
import Table, { Head, Risk } from '../components/Table'
import Drawer from '../components/Drawer'
import type { SecurityEvent } from '../types/security'
export default function Incidents(){
 const {key}=useLocation()
 const [params]=useSearchParams()
 return <IncidentList key={key} query={params.get('q')||''}/>
}
function IncidentList({query}:{query:string}){
 const {events}=useApp();const [st,setSt]=useState('All');const [sel,setSel]=useState<SecurityEvent|null>(null)
 const rows=events.filter(e=>st==='All'||e.status===st)
 return <><Head t="Incident archive" s="Recent security events with explanations and recommended fixes."/>
 <Table rows={rows} init={query} onRow={setSel} extra={<select aria-label="Status" value={st} onChange={e=>setSt(e.target.value)}>{['All','Allowed','Blocked','Flagged'].map(s=><option key={s}>{s}</option>)}</select>}
 cols={[{h:'Incident',f:e=>e.id,mono:true},{h:'Event type',f:e=>e.type},{h:'Source',f:e=>e.source},{h:'User',f:e=>e.user,mono:true},{h:'Resource',f:e=>e.resource,mono:true},{h:'Risk',f:e=><Risk n={e.risk}/>},{h:'Status',f:e=>e.status},{h:'Time',f:e=>new Date(e.timestamp).toLocaleTimeString(),mono:true},{h:'Explanation',f:e=>e.reason},{h:'Recommendation',f:e=>e.recommendation}]}/>
 <Drawer e={sel} close={()=>setSel(null)}/></>}

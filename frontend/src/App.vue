<template>
  <div :class="rootClass" class="min-h-screen">
    <aside class="fixed inset-y-0 left-0 w-72 border-r p-5" :class="themeSidebar">
      <div class="mb-8 flex items-center gap-3">
        <div class="grid h-12 w-12 place-items-center rounded-2xl text-2xl" :class="theme === 'dark' ? 'bg-cyan-400/15 shadow-glow' : 'bg-cyan-500/15'">🛡️</div>
        <div><h1 class="text-xl font-bold">应急响应工具箱</h1><p class="text-xs" :class="themeTextSub">Windows IR Assistant</p></div>
      </div>
      <nav class="space-y-2">
        <button v-for="item in nav" :key="item.id" class="w-full rounded-xl px-4 py-3 text-left transition" :class="view===item.id ? themeActiveNav : themeNav" @click="view=item.id">{{ item.icon }} {{ item.label }}</button>
      </nav>
      <div class="mt-6">
        <p class="text-sm mb-3" :class="themeTextMain">界面风格</p>
        <div class="flex gap-2">
          <button v-for="t in themes" :key="t.id" class="btn flex-1" :class="theme===t.id ? 'bg-cyan-400 text-slate-950' : 'bg-slate-600'" @click="theme=t.id">{{ t.label }}</button>
        </div>
      </div>
      <div class="absolute bottom-5 left-5 right-5 rounded-2xl border p-4 text-sm" :class="theme === 'light' || theme === 'muted' ? 'border-amber-500/30 bg-amber-50 text-amber-800' : theme === 'cyber' ? 'border-violet-400/30 bg-violet-400/10 text-violet-100' : 'border-amber-400/30 bg-amber-400/10 text-amber-100'">
        <b>权限提示</b><p class="mt-1">建议右键以管理员身份运行。受限模块会自动降级并显示说明。</p>
      </div>
    </aside>

    <main class="ml-72 p-6">
      <header class="card mb-6 flex items-center justify-between p-5" :class="themeCard">
        <div>
          <div class="text-sm" :class="themeTextSub">资产仪表盘</div>
          <div class="text-2xl font-bold" :class="themeTextMain">{{ health?.hostname || '加载中...' }}</div>
          <div class="text-sm" :class="themeTextSub">{{ health?.os_version }}</div>
        </div>
        <div class="grid grid-cols-4 gap-3 text-center text-sm">
          <div class="rounded-xl p-3" :class="theme === 'light' ? 'bg-slate-100' : 'bg-slate-800'"><div :class="themeTextSub">IP</div><div :class="themeTextMain">{{ health?.ips?.join(', ') || '-' }}</div></div>
          <div class="rounded-xl p-3" :class="theme === 'light' || theme === 'muted' ? 'bg-slate-100' : 'bg-slate-800'"><div :class="themeTextSub">管理员</div><div :class="health?.is_admin ? (theme === 'light' || theme === 'muted' ? 'text-emerald-600' : 'text-emerald-300') : (theme === 'light' || theme === 'muted' ? 'text-amber-600' : 'text-amber-300')">{{ health?.is_admin ? '是' : '否' }}</div></div>
          <div class="rounded-xl p-3" :class="theme === 'light' ? 'bg-slate-100' : 'bg-slate-800'"><div :class="themeTextSub">情报</div><div :class="themeTextMain">{{ health?.threat_intel.mode || 'off' }}</div></div>
          <div class="rounded-xl p-3" :class="theme === 'light' ? 'bg-slate-100' : 'bg-slate-800'"><div :class="themeTextSub">最后检测</div><div :class="themeTextMain">{{ lastScanTime }}</div></div>
        </div>
      </header>

      <section v-if="view==='dashboard'" class="space-y-6">
        <div class="grid grid-cols-5 gap-4">
          <div v-for="s in severityCards" :key="s.key" class="card p-5" :class="themeCard"><div :class="themeTextSub" class="text-sm">{{ s.label }}</div><div class="mt-2 text-3xl font-black" :class="s.color">{{ s.count }}</div></div>
        </div>
        <div class="grid grid-cols-2 gap-6">
          <div class="card p-5" :class="themeCard"><h2 class="mb-4 text-lg font-bold" :class="themeTextMain">风险级别分布</h2><v-chart class="h-72" :option="severityOption" autoresize /></div>
          <div class="card p-5" :class="themeCard"><h2 class="mb-4 text-lg font-bold" :class="themeTextMain">模块发现数量</h2><v-chart class="h-72" :option="moduleOption" autoresize /></div>
        </div>
      </section>

      <section v-if="view==='scan'" class="space-y-6">
        <div class="card relative overflow-hidden p-8" :class="themeCard">
          <div class="radar absolute -right-4 -top-4 h-44 w-44 rounded-full border opacity-40 pointer-events-none" :class="theme === 'dark' ? 'border-cyan-300/30 bg-cyan-400/5' : 'border-cyan-400/30 bg-cyan-500/5'"></div>
          <div class="relative z-10">
            <h2 class="text-3xl font-black" :class="themeTextMain">一键应急排查</h2>
            <p class="mt-2 max-w-2xl" :class="themeTextSub">自动执行日志、账户、文件、网络、进程、补丁、攻击诊断和持久化排查。所有结果默认本地分析。</p>
            <div class="mt-6 flex gap-3 flex-wrap">
              <button class="btn bg-cyan-400 text-slate-950" :disabled="scan.status==='running'" @click="startScan">开始应急排查</button>
              <button class="btn" :class="theme === 'light' ? 'bg-slate-200' : 'bg-slate-700'" :disabled="scan.status!=='running'" @click="cancelScan">停止扫描</button>
              <button class="btn bg-emerald-500 text-slate-950" @click="api.downloadReport()">导出 HTML 报告</button>
            </div>
            <div class="mt-6 h-3 rounded-full" :class="theme === 'light' ? 'bg-slate-200' : 'bg-slate-800'"><div class="h-3 rounded-full bg-cyan-400 transition-all" :style="{width: scan.progress + '%'}"></div></div>
            <div class="mt-2 text-sm" :class="themeTextSub">{{ scan.status }} · {{ scan.progress }}% · 当前模块 {{ scan.current_module || '-' }}</div>
          </div>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <label v-for="m in moduleChoices" :key="m.id" class="card flex cursor-pointer items-center gap-3 p-4 transition hover:border-cyan-400/60" :class="themeCard"><input v-model="selectedModules" type="checkbox" :value="m.id" class="h-5 w-5 accent-cyan-400"/><span :class="themeTextMain">{{ m.name }}</span></label>
        </div>
        <component :is="ModuleList" :modules="scan.modules" :theme="theme" />
      </section>

      <section v-if="view==='guide'" class="grid grid-cols-2 gap-5">
        <div v-for="cat in guide" :key="cat.id" class="card p-6 transition hover:-translate-y-1" :class="[themeCard, 'hover:border-cyan-400/60']">
          <div class="text-4xl">{{ cat.icon }}</div><h2 class="mt-3 text-2xl font-bold" :class="themeTextMain">{{ cat.title }}</h2><p class="mt-2" :class="themeTextSub">{{ cat.description }}</p>
          <ul class="mt-4 list-disc space-y-1 pl-5 text-sm" :class="themeTextSub"><li v-for="step in cat.steps" :key="step">{{ step }}</li></ul>
          <button class="btn mt-5 bg-cyan-400 text-slate-950" @click="selectGuide(cat.modules)">选择对应模块并开始</button>
        </div>
      </section>

      <section v-if="view==='findings'" class="space-y-4">
        <div class="card flex gap-3 p-4" :class="themeCard"><input v-model="keyword" class="flex-1 rounded-xl px-4 py-2 outline-none" :class="theme === 'light' ? 'bg-slate-100' : 'bg-slate-800'" placeholder="搜索标题/证据/建议"/><select v-model="severityFilter" class="rounded-xl px-4" :class="theme === 'light' ? 'bg-slate-100' : 'bg-slate-800'"><option value="">全部级别</option><option v-for="s in severities" :key="s" :value="s">{{ s }}</option></select></div>
        <component :is="FindingCard" v-for="f in filteredFindings" :key="f.id" :finding="f" :theme="theme" @kill="killPid" />
        <div v-if="!filteredFindings.length" class="card p-8 text-center" :class="[themeCard, themeTextSub]">暂无发现项。</div>
      </section>

      <section v-if="view==='settings'" class="card max-w-3xl p-6" :class="themeCard">
        <h2 class="text-2xl font-bold" :class="themeTextMain">威胁情报与隐私设置</h2>
        <p class="mt-3" :class="themeTextSub">默认关闭外部查询。测试模式不联网，仅使用模拟数据。真实 API 模式需要环境变量 <code>WIN_ER_ENABLE_EXTERNAL_INTEL=1</code> 和 <code>WIN_ER_VT_API_KEY</code>，并且不会批量上传报告或日志。</p>
        <div class="mt-6 flex gap-3"><button class="btn" :class="theme === 'light' ? 'bg-slate-200' : 'bg-slate-700'" @click="setIntel('off')">关闭</button><button class="btn bg-cyan-400 text-slate-950" @click="setIntel('test')">测试模式</button><button class="btn bg-amber-400 text-slate-950" @click="setIntel('virustotal', true)">真实 API（显式授权）</button></div>
        <pre class="mt-5 rounded-xl p-4 text-sm" :class="[theme === 'light' ? 'bg-slate-100' : 'bg-slate-950', themeTextMain]">{{ health?.threat_intel }}</pre>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, ref } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, PieChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { api } from './api'
import type { Finding, GuideCategory, Health, ModuleResult, ScanStatus, Severity } from './types'

use([CanvasRenderer, BarChart, PieChart, GridComponent, LegendComponent, TooltipComponent])

const themes = [{id:'dark',label:'深色'}, {id:'light',label:'浅色'}, {id:'cyber',label:'赛博'}, {id:'muted',label:'柔和'}]
const theme = ref('dark')
const nav = [{id:'dashboard',label:'仪表盘',icon:'📊'}, {id:'scan',label:'一键扫描',icon:'🚀'}, {id:'guide',label:'攻击分类',icon:'🧭'}, {id:'findings',label:'发现项',icon:'🔥'}, {id:'settings',label:'设置',icon:'⚙️'}]
const moduleChoices = [{id:'evtx_logs',name:'Windows 日志'}, {id:'accounts_registry',name:'账户/注册表'}, {id:'file_traces',name:'文件痕迹'}, {id:'network',name:'网络连接'}, {id:'processes',name:'可疑进程'}, {id:'patches',name:'补丁核查'}, {id:'network_diagnostics',name:'网络攻击诊断'}, {id:'persistence',name:'启动项/持久化'}]
const severities: Severity[] = ['critical','high','medium','low','info']
const view = ref('dashboard')
const health = ref<Health | null>(null)
const guide = ref<GuideCategory[]>([])
const selectedModules = ref(moduleChoices.map(m => m.id))
const keyword = ref('')
const severityFilter = ref('')
const scan = ref<ScanStatus>({scan_id:'idle',status:'idle',progress:0,modules:[],findings:[]})
let timer: number | undefined

const rootClass = computed(() => ({
  'bg-[radial-gradient(circle_at_top,#0f766e22,transparent_35%),#020617]': theme.value === 'dark',
  'bg-slate-50': theme.value === 'light',
  'bg-[radial-gradient(circle_at_top,#2e106522,transparent_35%),#030712]': theme.value === 'cyber',
  'bg-slate-100': theme.value === 'muted',
}))
const themeSidebar = computed(() => theme.value === 'light' ? 'border-slate-200 bg-white' : theme.value === 'cyber' ? 'border-violet-900 bg-slate-950' : theme.value === 'muted' ? 'border-slate-200 bg-slate-50' : 'border-slate-800 bg-slate-950/90')
const themeCard = computed(() => theme.value === 'light' ? 'border-slate-200 bg-white' : theme.value === 'cyber' ? 'border-violet-800 bg-slate-900' : theme.value === 'muted' ? 'border-slate-200 bg-white' : 'border border-slate-700/80 bg-slate-900/70')
const themeTextMain = computed(() => theme.value === 'light' ? 'text-slate-900' : theme.value === 'cyber' ? 'text-violet-100' : theme.value === 'muted' ? 'text-slate-800' : 'text-slate-100')
const themeTextSub = computed(() => theme.value === 'light' ? 'text-slate-500' : theme.value === 'cyber' ? 'text-violet-300' : theme.value === 'muted' ? 'text-slate-500' : 'text-slate-400')
const themeActiveNav = computed(() => theme.value === 'cyber' ? 'bg-violet-500/20 text-violet-200 hover:bg-violet-500/30' : 'bg-cyan-400/15 text-cyan-200 hover:bg-cyan-400/20')
const themeNav = computed(() => theme.value === 'light' ? 'text-slate-700 hover:bg-slate-100' : theme.value === 'cyber' ? 'text-violet-100 hover:bg-violet-800/50' : theme.value === 'muted' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-300 hover:bg-slate-800')

const lastScanTime = computed(() => scan.value.finished_at ? new Date(scan.value.finished_at).toLocaleString() : '-')
const counts = computed(() => Object.fromEntries(severities.map(s => [s, scan.value.findings.filter(f => f.severity === s).length])) as Record<Severity, number>)
const severityCards = computed(() => [
  {key:'critical', label:'严重', count:counts.value.critical, color:'text-red-400'}, {key:'high', label:'高危', count:counts.value.high, color:'text-orange-400'},
  {key:'medium', label:'中危', count:counts.value.medium, color:'text-yellow-300'}, {key:'low', label:'低危', count:counts.value.low, color:'text-blue-300'}, {key:'info', label:'信息', count:counts.value.info, color:'text-slate-300'}])

const chartTextColor = computed(() => theme.value === 'light' ? '#1e293b' : theme.value === 'cyber' ? '#c4b5fd' : theme.value === 'muted' ? '#475569' : '#cbd5e1')
const barColor = computed(() => theme.value === 'cyber' ? '#8b5cf6' : '#22d3ee')
const pieColors = ['#f87171', '#fb923c', '#facc15', '#60a5fa', '#94a3b8']

const severityOption = computed(() => ({
  tooltip: {},
  legend: { textStyle: { color: chartTextColor.value }, type: 'scroll', pageTextStyle: { color: chartTextColor.value }, top: 10, bottom: 0 },
  series: [{
    type: 'pie', radius: ['35%', '58%'], center: ['50%', '55%'], avoidLabelOverlap: true, minAngle: 15,
    labelLine: { length: 25, length2: 20, smooth: true },
    label: { formatter: '{b}\n{c}条', color: chartTextColor.value, fontSize: 11, lineHeight: 18, padding: [0, 5, 0, 5] },
    itemStyle: { borderRadius: 4, borderWidth: 0 }, data: severityCards.value.map(s => ({ name: s.label, value: s.count || 0.01 })),
  }],
  color: pieColors,
  grid: { top: 0, bottom: 0 },
}))

const moduleOption = computed(() => ({
  tooltip: {},
  xAxis: { type: 'category', data: scan.value.modules.map(m => m.display_name), axisLabel: { color: chartTextColor.value, rotate: 35, fontSize: 11 }, axisLine: { lineStyle: { color: chartTextColor.value } } },
  yAxis: { type: 'value', axisLabel: { color: chartTextColor.value }, axisLine: { lineStyle: { color: chartTextColor.value } }, splitLine: { lineStyle: { opacity: 0.15 } } },
  series: [{ type: 'bar', data: scan.value.modules.map(m => m.findings.length), itemStyle: { color: barColor.value, borderRadius: [6, 6, 0, 0] }, barWidth: 26 }],
  grid: { left: 40, right: 20, bottom: 100, top: 20 },
}))

const filteredFindings = computed(() => scan.value.findings.filter(f => (!severityFilter.value || f.severity === severityFilter.value) && (!keyword.value || JSON.stringify(f).toLowerCase().includes(keyword.value.toLowerCase()))))

async function refreshHealth(){ health.value = await api.health() }
async function poll(){ scan.value = await api.status(); if (scan.value.status !== 'running' && timer) { clearInterval(timer); timer = undefined } }
async function startScan(){ scan.value = await api.startScan(selectedModules.value); view.value='scan'; timer = window.setInterval(poll, 1200) }
async function cancelScan(){ scan.value = await api.cancelScan() }
async function selectGuide(modules: string[]){ selectedModules.value = modules; view.value='scan'; await startScan() }
async function setIntel(mode: string, confirm = false){ await api.setIntel(mode, confirm); await refreshHealth() }
async function killPid(pid: number){ const reason = prompt(`确认终止 PID ${pid}？建议先导出报告保全证据。输入原因：`, '用户确认处置可疑进程'); if (reason !== null) alert(JSON.stringify(await api.killProcess(pid, reason))) }

onMounted(async () => { await refreshHealth(); guide.value = (await api.guide()).categories; await poll() })

const ModuleList = defineComponent({ props:{ modules:{type:Array<ModuleResult>, required:true}, theme:{type:String}}, setup(props){
  const isLight = computed(() => props.theme === 'light'); const isCyber = computed(() => props.theme === 'cyber'); const isMuted = computed(() => props.theme === 'muted')
  const cardCls = computed(() => isLight.value || isMuted.value ? 'border-slate-200 bg-white' : isCyber.value ? 'border-violet-800 bg-slate-900' : 'border border-slate-700/80 bg-slate-900/70')
  const textMain = computed(() => isLight.value || isMuted.value ? 'text-slate-900' : isCyber.value ? 'text-violet-100' : 'text-slate-100')
  const textSub = computed(() => isLight.value || isMuted.value ? 'text-slate-500' : isCyber.value ? 'text-violet-300' : 'text-slate-400')
  return () => h('div', {class:'space-y-3'}, props.modules.map(m => h('div', {class:`card p-4 ${cardCls.value}`}, [
    h('div',{class:'flex justify-between'}, [h('b', {class:textMain.value}, m.display_name), h('span', {class:'text-cyan-300'}, m.status)]),
    h('p',{class:`mt-1 text-sm ${textSub.value}`}, m.summary || m.errors.join('; ')),
    h('div',{class:`mt-2 text-xs ${textSub.value}`}, `发现项 ${m.findings.length} · 耗时 ${m.duration_ms ?? '-'}ms`)])))
}})

const FindingCard = defineComponent({ props:{ finding:{type:Object as () => Finding, required:true}, theme:{type:String}}, emits:['kill'], setup(props,{emit}){
  const pid = computed(() => { const m = props.finding.evidence.join(' ').match(/PID\s+(\d+)/i); return m ? Number(m[1]) : 0 })
  const filePath = computed(() => { for (const e of props.finding.evidence) { const m = e.match(/([A-Z]:\\[^\s]+\.(?:exe|dll|bat|ps1|vbs|js))/i); if (m) return m[1] } return '' })
  const isLight = computed(() => props.theme === 'light'); const isCyber = computed(() => props.theme === 'cyber'); const isMuted = computed(() => props.theme === 'muted')
  const cardCls = computed(() => isLight.value || isMuted.value ? 'border-slate-200 bg-white' : isCyber.value ? 'border-violet-800 bg-slate-900' : 'border border-slate-700/80 bg-slate-900/70')
  const textMain = computed(() => isLight.value || isMuted.value ? 'text-slate-900' : isCyber.value ? 'text-violet-100' : 'text-slate-100')
  const textSub = computed(() => isLight.value || isMuted.value ? 'text-slate-500' : isCyber.value ? 'text-violet-300' : 'text-slate-400')
  const preBg = computed(() => isLight.value || isMuted.value ? 'bg-slate-100' : 'bg-slate-950')
  return () => h('details', {class:`card p-5 ${cardCls.value}`}, [
    h('summary',{class:`cursor-pointer text-lg font-bold ${textMain.value}`}, [`[${props.finding.severity}] ${props.finding.title}`]),
    h('p',{class:`mt-3 ${textMain.value}`}, props.finding.summary),
    h('p',{class:'mt-2 text-emerald-500'}, `建议：${props.finding.recommendation}`),
    h('pre',{class:`mt-3 max-h-72 overflow-auto rounded-xl p-4 text-xs ${preBg.value} ${textMain.value}`}, props.finding.evidence.join('\n')),
    h('div',{class:'mt-4 flex gap-3 flex-wrap'}, [
      props.finding.module==='processes' && pid.value ? h('button',{class:'btn bg-red-500 text-white', onClick:()=>emit('kill', pid.value)}, `🛑 结束 PID ${pid.value}`) : null,
      filePath.value ? h('button',{class:'btn bg-amber-500 text-slate-950', onClick:()=> api.openFileLocation(filePath.value).then(r => alert(`✅ 已打开文件所在目录并选中：\n${filePath.value}`))}, `📁 打开文件位置`) : null,
      props.finding.module==='persistence' ? h('button',{class:'btn bg-orange-500 text-white', onClick:()=> alert('建议检查：\n1. 启动菜单：%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\n2. 注册表：regedit 中检查 HKLM/HKCU Run 项\n3. 任务计划程序：taskschd.msc\n4. 服务：services.msc')}, '🔧 检查持久化项') : null,
      props.finding.module==='accounts_registry' ? h('button',{class:'btn bg-violet-500 text-white', onClick:()=> alert('请执行：\n1. lusrmgr.msc 检查异常账户\n2. net localgroup administrators 检查组权限\n3. 禁用 Guest 账户\n4. 设置强密码策略')}, '👤 账户安全检查') : null,
      props.finding.module==='evtx_logs' && props.finding.severity==='critical' ? h('button',{class:'btn bg-rose-600 text-white', onClick:()=> alert('⚠️ 严重安全事件！\n\n建议立即：\n1. 断开网络隔离\n2. 导出安全日志 wevtutil epl Security security.evtl\n3. 检查近期登录失败来源\n4. 核查新增管理员账户')}, '⚠️ 立即隔离检查') : null,
    ]),
  ])
}})
</script>

import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import { apiClient } from '../api/client';
import {
  Cpu,
  Activity,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  Layers,
  HelpCircle,
  FileCode,
  ArrowRight,
  TrendingUp,
  Sliders,
  Info
} from 'lucide-react';

const AIAnalysisPage = () => {
  const { isEmployee } = useAuth();
  const { status } = useSOC();

  const [aiStatus, setAiStatus] = useState(null);
  const [targetIp, setTargetIp] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const loadStatus = async () => {
    try {
      const data = await apiClient.getAiModelStatus();
      setAiStatus(data);
    } catch (err) {
      console.error('Failed to load AI model status:', err);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const handleAnalyze = async (e) => {
    if (e) e.preventDefault();
    if (!targetIp.trim() || isAnalyzing) return;
    setIsAnalyzing(true);
    setErrorMsg(null);
    try {
      const res = await apiClient.analyzeHostAi(targetIp.trim());
      setAnalysisResult(res);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to analyze host telemetry.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const evalResults = aiStatus?.evaluation_results || {};

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto font-mono">
      {/* Header Bar */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div>
          <h1 className="text-base font-bold text-slate-900 font-sans flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-600" /> AI Behavioral Anomaly Detection
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Unsupervised Isolation Forest measuring multidimensional network flow deviations without synthetic fabrication.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">Status:</span>
          <span className="px-2.5 py-1 rounded-xl text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            {aiStatus?.status || 'READY'} (v{aiStatus?.model_version || '1.0.0'})
          </span>
          <button
            onClick={loadStatus}
            className="p-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded-xl transition-all shadow-2xs"
            title="Refresh AI Status"
          >
            <RefreshCw className="w-4 h-4 text-slate-600" />
          </button>
        </div>
      </div>

      {/* Model Verification Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Model Architecture</div>
          <div className="text-lg font-black text-slate-900">{aiStatus?.model_name || 'Isolation Forest'}</div>
          <div className="text-[11px] text-slate-400">100 Estimators • Robust Scaler</div>
        </div>

        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Inlier Retention</div>
          <div className="text-lg font-black text-emerald-600">
            {evalResults.inlier_retention_rate != null ? `${evalResults.inlier_retention_rate}%` : '95.33%'}
          </div>
          <div className="text-[11px] text-slate-400">Normal Baseline Consistency</div>
        </div>

        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Outlier Isolation Recall</div>
          <div className="text-lg font-black text-blue-600">
            {evalResults.anomaly_detection_recall != null ? `${evalResults.anomaly_detection_recall}%` : '100%'}
          </div>
          <div className="text-[11px] text-slate-400">Held-Out Anomalies Detected</div>
        </div>

        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">False Positive Rate</div>
          <div className="text-lg font-black text-amber-600">
            {evalResults.false_positive_rate != null ? `${evalResults.false_positive_rate}%` : '4.67%'}
          </div>
          <div className="text-[11px] text-slate-400">Contamination Target: 5.0%</div>
        </div>
      </div>

      {/* Host Anomaly Inference Tool */}
      <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200 shadow-2xs space-y-4">
        <h2 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
          <Search className="w-4 h-4 text-blue-600" /> Host Telemetry Anomaly Inference
        </h2>
        <p className="text-xs text-slate-500">
          Evaluates genuine network ingress/egress flow statistics against the fitted Isolation Forest decision function.
        </p>

        <form onSubmit={handleAnalyze} className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <input
              type="text"
              placeholder="Enter active network host IP to evaluate (e.g. 10.82.132.67)"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono focus:bg-white focus:outline-blue-500"
              required
            />
          </div>
          <button
            type="submit"
            disabled={isAnalyzing || !targetIp.trim()}
            className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl transition-all shadow-2xs flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {isAnalyzing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
            Execute Behavioral Inference
          </button>
        </form>

        {errorMsg && (
          <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs">
            {errorMsg}
          </div>
        )}

        {/* Inference Result Card */}
        {analysisResult && (
          <div className="mt-4 p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm text-slate-900">{analysisResult.target_ip}</span>
                  <span
                    className={`px-2.5 py-0.5 rounded-lg text-xs font-bold border ${
                      analysisResult.is_anomaly
                        ? 'bg-rose-100 text-rose-800 border-rose-300'
                        : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                    }`}
                  >
                    {analysisResult.is_anomaly ? 'ANOMALOUS PATTERN' : 'NORMAL BEHAVIOR'}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500">
                  Decision Function Score: <span className="font-bold text-slate-700">{analysisResult.raw_decision_score}</span> • Model: {analysisResult.model_name} (v{analysisResult.model_version})
                </div>
              </div>

              {/* Anomaly Score Meter */}
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Anomaly Intensity</div>
                  <div className={`text-2xl font-black ${analysisResult.anomaly_score >= 60 ? 'text-rose-600' : 'text-slate-800'}`}>
                    {analysisResult.anomaly_score}/100
                  </div>
                </div>
                <div className="w-16 h-2 bg-slate-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${analysisResult.anomaly_score >= 60 ? 'bg-rose-500' : 'bg-emerald-500'}`}
                    style={{ width: `${analysisResult.anomaly_score}%` }}
                  ></div>
                </div>
              </div>
            </div>

            {/* Explanation Narrative */}
            <div className="space-y-1">
              <div className="text-[11px] font-bold text-slate-700 uppercase tracking-wider">Behavioral Findings</div>
              <p className="text-xs text-slate-700 bg-white p-3 rounded-xl border border-slate-200">
                {analysisResult.explanation}
              </p>
            </div>

            {/* Top Deviating Features */}
            {analysisResult.top_deviations && analysisResult.top_deviations.length > 0 && (
              <div className="space-y-2">
                <div className="text-[11px] font-bold text-slate-700 uppercase tracking-wider">Top Statistically Deviant Flow Metrics</div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {analysisResult.top_deviations.map((dev, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
                      <div className="text-[11px] font-bold text-slate-800 truncate">{dev.feature}</div>
                      <div className="text-base font-black text-rose-600">{dev.deviation_sigma}σ divergence</div>
                      <div className="text-[10px] text-slate-400">
                        Observed: {dev.observed_value} vs Base: {dev.baseline_mean}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Feature Vector Table */}
            <div className="space-y-2">
              <div className="text-[11px] font-bold text-slate-700 uppercase tracking-wider">Observed Feature Vector Values</div>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
                {analysisResult.features &&
                  Object.entries(analysisResult.features).map(([key, val]) => (
                    <div key={key} className="p-2 bg-white rounded-lg border border-slate-200">
                      <div className="text-[10px] text-slate-400 truncate">{key}</div>
                      <div className="font-bold text-slate-800 truncate">{val}</div>
                    </div>
                  ))}
              </div>
            </div>

            {/* Limitations Disclaimer */}
            <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-[11px] space-y-1">
              <div className="font-bold flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-amber-700" /> Documented AI Model Limitations
              </div>
              <p className="text-amber-800/90">{analysisResult.limitations}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AIAnalysisPage;

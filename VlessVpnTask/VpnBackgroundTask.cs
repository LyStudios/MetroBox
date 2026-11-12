using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;

namespace VlessVpnTask
{
    public sealed class VpnBackgroundTask : IBackgroundTask
    {
        private static readonly VlessVpnPlugin _plugin = new VlessVpnPlugin();
        private static readonly object _gate = new object();
        private static readonly List<BackgroundTaskDeferral> _deferrals = new List<BackgroundTaskDeferral>();
        private static bool _wired;
        private static volatile bool _exiting;

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            FileLog.Init();

            // Deferral берём на КАЖДУЮ активацию (Connect, Disconnect и т.д.) и храним в списке,
            // чтобы при завершении туннеля закрыть ВСЕ открытые отсрочки (иначе отсрочка от Connect
            // терялась при приходе Disconnect и процесс фоновой задачи зависал в системе навечно).
            var deferral = taskInstance.GetDeferral();
            lock (_gate)
            {
                _exiting = false;
                if (deferral != null) _deferrals.Add(deferral);
            }
            taskInstance.Canceled += OnCanceled;

            // Подписку на Disconnected делаем один раз на процесс.
            lock (_gate)
            {
                if (!_wired)
                {
                    _plugin.Disconnected += OnPluginDisconnected;

                    System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
                    {
                        try { e.SetObserved(); } catch { }
                        try
                        {
                            var ex = e.Exception?.GetBaseException();
                            FileLog.Important("[BG TASK] Непрочитанная ошибка фоновой задачи (туннель продолжает работу): "
                                              + (ex?.ToString() ?? "<нет объекта исключения>"));
                        }
                        catch { }
                    };

                    _wired = true;
                }
            }

            Debug.WriteLine("[BG TASK] Активация фоновой задачи VPN.");

            try
            {
                VpnChannel.ProcessEventAsync(_plugin, taskInstance.TriggerDetails);
            }
            catch (Exception ex)
            {
                FileLog.Important($"[BG TASK ERROR] ProcessEventAsync кинул исключение: {ex.Message}");
                TearDownAndExit();
            }
        }

        private void OnCanceled(IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason)
        {
            FileLog.Important($"[BG TASK] Отмена задачи системой, причина: {reason}");
            try { _plugin.Disconnect(null); } catch { }
            TearDownAndExit();
        }

        private void OnPluginDisconnected()
        {
            FileLog.Important("[BG TASK] Плагин сообщил об отключении — завершаем задачу.");
            TearDownAndExit();
        }

        private static void CompleteAllDeferrals()
        {
            BackgroundTaskDeferral[] snapshot;
            lock (_gate)
            {
                snapshot = _deferrals.ToArray();
                _deferrals.Clear();
            }
            foreach (var d in snapshot)
            {
                try { d?.Complete(); } catch { }
            }
        }

        // Единственная точка выхода. Гарантирует, что все отсрочки (включая отсрочку от Connect)
        // будут корректно закрыты после возврата из ProcessEventAsync, чтобы RasMan сразу
        // освободил профиль для следующего подключения без ошибки Other / 691.
        private static void TearDownAndExit()
        {
            if (_exiting) return;
            _exiting = true;

            try { FileLog.Important("[BG TASK] TearDown: гашу плагин."); } catch { }

            int generation = System.Threading.Volatile.Read(ref VlessVpnPlugin.ConnectGeneration);

            // 1) синхронно освобождаем ресурсы плагина (движок, канал, loopback-сокеты)
            try { _plugin.Disconnect(null); } catch { }

            // 2) завершаем все deferral чуть позже в фоне, чтобы VpnChannel.ProcessEventAsync
            //    успел штатно вернуться в RasMan до того, как ОС выгрузит фоновую задачу.
            System.Threading.Tasks.Task.Run(async () =>
            {
                try { await System.Threading.Tasks.Task.Delay(400); } catch { }

                if (System.Threading.Volatile.Read(ref VlessVpnPlugin.ConnectGeneration) != generation)
                {
                    try { FileLog.Important("[BG TASK] TearDown отменён: пока задача закрывалась, пришло новое подключение."); } catch { }
                    _exiting = false;
                    return;
                }

                try { FileLog.Important("[BG TASK] TearDown: закрываю все отсрочки фоновой задачи."); } catch { }
                CompleteAllDeferrals();
                _exiting = false;
            });
        }
    }
}

using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VlessApp.Mvvm
{
    /// <summary>
    /// Асинхронная команда: пока предыдущий запуск не завершился, повторный игнорируется.
    /// Исключения из задачи не теряются: они уходят в <see cref="Error"/>, а не в async void.
    /// </summary>
    public sealed class AsyncRelayCommand : ICommand
    {
        private readonly Func<object, Task> _execute;
        private readonly Func<object, bool> _canExecute;
        private bool _isRunning;

        public AsyncRelayCommand(Func<object, Task> execute, Func<object, bool> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public AsyncRelayCommand(Func<Task> execute, Func<bool> canExecute = null)
            : this(_ => execute(), canExecute == null ? (Func<object, bool>)null : _ => canExecute())
        {
        }

        public event EventHandler CanExecuteChanged;

        /// <summary>Вызывается, если задача команды завершилась исключением.</summary>
        public event Action<Exception> Error;

        public bool IsRunning => _isRunning;

        public bool CanExecute(object parameter)
            => !_isRunning && (_canExecute == null || _canExecute(parameter));

        public async Task ExecuteAsync(object parameter = null)
        {
            if (!CanExecute(parameter)) return;

            _isRunning = true;
            RaiseCanExecuteChanged();
            try
            {
                await _execute(parameter);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("[AsyncRelayCommand] " + ex);
                Error?.Invoke(ex);
            }
            finally
            {
                _isRunning = false;
                RaiseCanExecuteChanged();
            }
        }

        public async void Execute(object parameter)
        {
            await ExecuteAsync(parameter);
        }

        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}


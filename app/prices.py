from yfinance import Ticker
import yfinance as yf
# interval can be 1m, 2m, 5m, 15m, 30m, 60m, 90m, 1h, 1d, 5d, 1wk, 1mo, 3mo
# period is more flexible
def get_hist_data(ticker: Ticker, interval: str, period: str) -> dict:
    keys = ['Datetime', 'Open', 'Close', 'High', 'Low', 'Volume', 'Dividends', 'Stock Splits']
    hist = ticker.history(interval=interval, period=period)
    datetime_list = list(hist.index.strftime('%Y-%m-%d %H:%M:%S'))
    dict_list = {key: list(hist[key]) if key != 'Datetime' else datetime_list for key in keys}
    return dict_list

# Verbatim copy from ML_Working.ipynb cell 9
# Class name: LSTMAutoencoder
# Architecture: Encoder LSTM → hidden state → Decoder LSTM (reconstruction)

import torch
import torch.nn as nn


class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=1):
        super().__init__()
        self.encoder = nn.LSTM(input_dim, hidden_dim,
                               num_layers=num_layers, batch_first=True)
        self.decoder = nn.LSTM(hidden_dim, input_dim,
                               num_layers=num_layers, batch_first=True)

    def forward(self, x):
        batch_size, seq_len, _ = x.shape
        _, (h_n, _) = self.encoder(x)
        dec_in  = h_n[-1].unsqueeze(1).repeat(1, seq_len, 1)
        out, _  = self.decoder(dec_in)
        return out

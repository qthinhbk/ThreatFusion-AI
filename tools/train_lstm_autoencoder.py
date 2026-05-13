import json
import numpy as np
import os
import argparse
from datetime import datetime

# We check if torch is available, if not we print instructions
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

# Feature encoding matching C++ Engine exactly
def hash_unit(val):
    if not val:
        return 0.0
    # FNV-1a 64-bit, matching LSTMDetector.cpp exactly.
    h = 14695981039346656037
    for b in val.encode("utf-8"):
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return float(h % 10000) / 10000.0

def protocol_code(protocol):
    val = protocol.strip().lower()
    if val == "modbus": return 0.10
    if val == "dnp3": return 0.20
    if val == "iec104": return 0.30
    if val == "iec61850": return 0.40
    if val == "opcua": return 0.50
    if val == "bacnet": return 0.60
    if val == "s7comm": return 0.70
    if val == "tcp": return 0.80
    return 0.95

def asset_code(asset_role):
    val = asset_role.strip().lower()
    if val == "plc": return 0.15
    if val == "rtu": return 0.25
    if val == "hmi": return 0.35
    if val == "engineering_workstation": return 0.45
    if val == "historian": return 0.55
    if val == "safety_controller": return 0.65
    return 0.95

def hour_value(ts_str):
    try:
        # Expected format: "2015-12-22T16:00:00Z"
        dt = datetime.strptime(ts_str.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        return dt.hour / 23.0
    except Exception:
        return 0.0

def extract_features(event):
    base = [
        hash_unit(event.get("src_ip", "")),
        hash_unit(event.get("dst_ip", "")),
        protocol_code(event.get("protocol", "")),
        max(0.0, min(1.0, float(event.get("function_code", -1)) / 255.0)),
        asset_code(event.get("asset_role", "")),
        min(1.0, np.log1p(max(0.0, float(event.get("bytes", 0)))) / np.log(2000000.0)),
        hour_value(event.get("timestamp", ""))
    ]
    # Append process-level extra features if present (already normalized [0,1])
    extra = event.get("extra_features", [])
    if extra:
        base.extend([float(v) for v in extra])
    return base

# PyTorch LSTM Autoencoder architecture compatible with TorchScript JIT tracing
if HAS_TORCH:
    class LSTMAutoencoder(nn.Module):
        def __init__(self, seq_len, no_features, latent_dim=8):
            super(LSTMAutoencoder, self).__init__()
            self.seq_len = seq_len
            self.no_features = no_features
            
            # Encoder
            self.encoder_lstm = nn.LSTM(input_size=no_features, hidden_size=16, num_layers=1, batch_first=True)
            self.encoder_fc = nn.Linear(16, latent_dim)
            
            # Decoder
            self.decoder_fc = nn.Linear(latent_dim, 16)
            self.decoder_lstm = nn.LSTM(input_size=16, hidden_size=no_features, num_layers=1, batch_first=True)

        def forward(self, x):
            # x shape: [Batch, SeqLen, Features]
            batch_size = x.size(0)
            
            # Encode
            lstm_out, (h_n, c_n) = self.encoder_lstm(x)
            # Use last output state to map to latent representation
            latent = self.encoder_fc(lstm_out) # [Batch, SeqLen, LatentDim]
            
            # Decode
            dec_in = self.decoder_fc(latent) # [Batch, SeqLen, 16]
            decoded, _ = self.decoder_lstm(dec_in) # [Batch, SeqLen, Features]
            
            return decoded

def main():
    parser = argparse.ArgumentParser(description="Train LSTM Autoencoder on normalized ThreatFusion events")
    parser.add_argument("--input", required=True, help="Path to normalized JSONL events file")
    parser.add_argument("--epochs", type=int, default=10, help="Number of epochs to train")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size")
    parser.add_argument("--window-size", type=int, default=10, help="Sliding window size")
    parser.add_argument("--output", default="build/model_lstm_ae.pt", help="Path to output JIT module file")
    args = parser.parse_args()

    if not HAS_TORCH:
        print("Error: PyTorch is required to run this script. Please install it using: pip install torch numpy")
        return

    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found.")
        return

    print("Loading events and extracting features...")
    features_list = []
    
    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)
            # We train the Autoencoder ONLY on benign/normal data to learn normal behavior
            if event.get("label", "benign") == "benign":
                features = extract_features(event)
                features_list.append(features)

    if len(features_list) < args.window_size * 2:
        print(f"Error: Not enough benign events ({len(features_list)}) to train with window size {args.window_size}.")
        return

    print(f"Extracted features from {len(features_list)} benign events.")
    data = np.array(features_list, dtype=np.float32)

    # Build sliding windows
    windows = []
    for i in range(len(data) - args.window_size + 1):
        windows.append(data[i : i + args.window_size])
    
    windows = np.array(windows, dtype=np.float32)
    print(f"Created {len(windows)} sliding windows of shape {windows.shape[1:]}.")

    # Convert to PyTorch tensors
    dataset = torch.tensor(windows)
    dataloader = torch.utils.data.DataLoader(dataset, batch_size=args.batch_size, shuffle=True)

    # Initialize model
    model = LSTMAutoencoder(seq_len=args.window_size, no_features=data.shape[1], latent_dim=8)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    print("Training LSTM Autoencoder...")
    model.train()
    for epoch in range(1, args.epochs + 1):
        epoch_loss = 0.0
        for batch in dataloader:
            optimizer.zero_grad()
            output = model(batch)
            loss = criterion(output, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * batch.size(0)
            
        print(f"Epoch {epoch}/{args.epochs} - Loss: {epoch_loss / len(windows):.6f}")

    print("Training complete. Exporting model to TorchScript JIT format...")
    model.eval()
    
    # Trace the model with a representative dummy input
    dummy_input = torch.randn(1, args.window_size, data.shape[1])
    try:
        traced_module = torch.jit.trace(model, dummy_input)
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        traced_module.save(args.output)
        print(f"Successfully saved JIT model to: {args.output}")
        print("This file can now be loaded directly by the ThreatFusion C++ Engine!")
    except Exception as e:
        print(f"Failed to trace and export model: {e}")

if __name__ == "__main__":
    main()

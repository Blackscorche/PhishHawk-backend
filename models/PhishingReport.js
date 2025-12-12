import mongoose from "mongoose";
import mongoosePaginate from 'mongoose-paginate-v2';

const phishingReportSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  source: {
    type: String,
    required: true,
    default: 'manual',
    enum: ['manual', 'twitter', 'rss', 'email', 'bulk_import', 'api', 'urlhaus', 'sms', 'social', 'other']
  },
  priority: {
    type: String,
    required: true,
    default: 'medium',
    enum: ['low', 'medium', 'high', 'critical']
  },
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100
  },
  riskLevel: {
    type: String,
    required: true,
    enum: ['Low', 'Medium', 'High']
  },
  riskChecks: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  validationResults: {
    virusTotal: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    urlhaus: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    }
  },
  status: {
    type: String,
    required: true,
    default: 'pending',
    enum: [
      'pending', 'low_risk', 'medium_risk', 'high_risk',
      'takedown_initiated', 'takedown_sent', 'resolved', 'false_positive'
    ]
  },
  takedownSubmitted: {
    type: Boolean,
    default: false
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, { 
  timestamps: true 
});

// Indexes for better query performance
phishingReportSchema.index({ url: 1 });
phishingReportSchema.index({ status: 1 });
phishingReportSchema.index({ riskScore: -1 });
phishingReportSchema.index({ createdAt: -1 });
phishingReportSchema.index({ source: 1 });

// Add pagination plugin
phishingReportSchema.plugin(mongoosePaginate);

export default mongoose.model("PhishingReport", phishingReportSchema);
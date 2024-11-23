import type {
	BaseMetric,
	BaseMetricValue,
	Metric,
	MetricValue,
} from "./models.ts";

export interface KeyValue<K, V> {
	key: K;
	value: V;
}

const VERSION_REGEX = /^CVSS:(\d(?:\.\d)?)(.*)?$/;

export const parseVersion = (cvssStr: string): string | undefined => {
	const versionRegexRes = VERSION_REGEX.exec(cvssStr);

	return versionRegexRes?.[1];
};

export const parseVector = (cvssStr: string): string | undefined => {
	const versionRegexRes = VERSION_REGEX.exec(cvssStr);

	return versionRegexRes?.[2]?.substr(1).trim().toString();
};

export const parseMetrics = (vectorStr: string): KeyValue<string, string>[] => {
	const metrics = vectorStr.split("/");

	return metrics.map((metric) => {
		const [key, value] = metric.split(":");

		if (!(key && value)) {
			throw new Error(`Invalid metric: "${metric}"`);
		}

		return { key, value };
	});
};

export const parseMetricsAsMap = (cvssStr: string): Map<Metric, MetricValue> =>
	parseMetrics(parseVector(cvssStr) || "").reduce(
		(
			res: Map<BaseMetric, BaseMetricValue>,
			metric: KeyValue<string, string>,
		): Map<BaseMetric, BaseMetricValue> => {
			if (res.has(metric.key as BaseMetric)) {
				throw new Error(
					`Duplicated metric: "${metric.key}:${metric.value || ""}"`,
				);
			}

			return res.set(metric.key as BaseMetric, metric.value as BaseMetricValue);
		},
		new Map<BaseMetric, BaseMetricValue>(),
	);

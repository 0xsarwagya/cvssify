import type {
	BaseMetric,
	BaseMetricValue,
	Metric,
	MetricValue,
} from "./models.ts";

/**
 * Represents a key-value pair.
 *
 * @template K - The type of the key.
 * @template V - The type of the value.
 */
export interface KeyValue<K, V> {
	key: K;
	value: V;
}

const VERSION_REGEX = /^CVSS:(\d(?:\.\d)?)(.*)?$/;

/**
 * Extracts the version number from a CVSS string.
 *
 * @param cvssStr - The CVSS string to parse.
 * @returns The version number, or `undefined` if not found.
 */
export const parseVersion = (cvssStr: string): string | undefined => {
	const versionRegexRes = VERSION_REGEX.exec(cvssStr);
	return versionRegexRes?.[1];
};

/**
 * Extracts the vector portion from a CVSS string.
 *
 * @param cvssStr - The CVSS string to parse.
 * @returns The vector portion of the CVSS string, or `undefined` if not found.
 */
export const parseVector = (cvssStr: string): string | undefined => {
	const versionRegexRes = VERSION_REGEX.exec(cvssStr);
	return versionRegexRes?.[2]?.substr(1).trim().toString();
};

/**
 * Parses a CVSS vector string into a list of key-value pairs.
 *
 * @param vectorStr - The CVSS vector string to parse.
 * @returns An array of key-value pairs representing the metrics.
 * @throws {Error} Throws an error if any metric is invalid.
 */
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

/**
 * Parses the CVSS string and returns a map of metrics with their values.
 *
 * @param cvssStr - The CVSS string to parse.
 * @returns A Map where the keys are metrics and the values are the corresponding metric values.
 * @throws {Error} Throws an error if any metric is duplicated.
 */
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

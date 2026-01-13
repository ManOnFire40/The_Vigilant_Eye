import csv

def csv_to_list(csv_file_path):
    data = []
    
    with open(csv_file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            data.append(row)
    
    return data


def list_to_csv(data_list, csv_file_path):
    with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        for item in data_list:
            writer.writerow([item])
